//! AST-backed anchors for declarations in one explicitly pinned Go package.
//!
//! This module only relates selected source bytes to parser nodes. It does not
//! qualify module acquisition, resolve imported declarations, or admit a CSMI
//! profile. Generic method receiver ownership uses a unique same-package base
//! declaration; imported, ambiguous, and malformed receivers remain unknown.

use super::GoPinnedPackage;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCallableValuesPayload;

use brokk_bifrost_analysis::analyzer::semantic_model::AnonymousCallableIdentity;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProducerLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::CatalogCallableValueFact;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExactArtifact;

use brokk_bifrost_analysis::analyzer::semantic_model::SourceAnchor;

use brokk_bifrost_analysis::analyzer::semantic_model::SourceByteRange;

use brokk_bifrost_analysis::analyzer::semantic_model::SourceCallableShape;

use brokk_bifrost_analysis::analyzer::semantic_model::SourceDeclarationKind;

use brokk_bifrost_analysis::analyzer::semantic_model::SourceParameterShape;

use brokk_bifrost_analysis::analyzer::semantic_model::SourceTypeNode;

use brokk_bifrost_go::declarations::{
    children_by_field, determine_go_package_name, go_method_receiver_type_node,
    is_predeclared_go_type,
};
use brokk_bifrost_go::parse::parse_go_with_cancellation;
use brokk_bifrost_semantic::analyzer::semantic_model::validate::is_canonical_relative_path;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GoSourceDeclarationKind {
    Function,
    Method,
    FunctionLiteral,
    Type,
    TypeAlias,
    StructField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoSourceByteRange {
    /// Inclusive UTF-8 byte offset in the exact source entry.
    pub start: usize,
    /// Exclusive UTF-8 byte offset in the exact source entry.
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoSourceAnchor {
    pub file: String,
    pub byte_range: GoSourceByteRange,
    pub kind: GoSourceDeclarationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoSourceName {
    pub text: String,
    pub byte_range: GoSourceByteRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoSourceTypeNode {
    pub file: String,
    pub byte_range: GoSourceByteRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoReceiverOwnerUnknown {
    /// This adapter has syntax and package membership, but no package-scope
    /// type-resolution evidence with which to bind the receiver declaration.
    TypeResolutionUnavailable,
    /// The parser did not expose one unambiguous receiver type node.
    ReceiverSyntaxUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoReceiverTypeOwner {
    Exact(GoSourceAnchor),
    Unknown {
        reason: GoReceiverOwnerUnknown,
        syntax_range: Option<GoSourceByteRange>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoStructFieldIdentity {
    pub anchor: GoSourceAnchor,
    pub owner: GoSourceAnchor,
    /// Explicit member names retain their AST token ranges. Embedded fields
    /// have no name token and retain an empty list.
    pub name_anchors: Vec<GoSourceName>,
    pub embedded: bool,
    pub type_node: GoSourceTypeNode,
    pub outer_type_shape: GoOuterTypeShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoFunctionParameterShape {
    /// Exact AST range of the parameter's type node.
    pub type_node: GoSourceTypeNode,
    pub variadic: bool,
    pub arity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoFunctionTypeShape {
    /// Exact AST range for the function type or literal signature header.
    pub function_type: GoSourceTypeNode,
    pub parameters: Vec<GoFunctionParameterShape>,
    pub results: Vec<GoFunctionParameterShape>,
    /// Package-scope declarations followed through exact AST type bindings,
    /// outer declaration first. No names are synthesized for these anchors.
    pub declaration_chain: Vec<GoSourceAnchor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoDeclaredTypeUnknown {
    UnresolvedPackageType,
    AmbiguousPackageType,
    TypeCycle,
    UnsupportedTypeSyntax,
    InvalidAstShape,
    NodeBudgetExhausted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoOuterTypeShape {
    Function(GoFunctionTypeShape),
    Other {
        syntax_kind: String,
        syntax: GoSourceTypeNode,
        declaration_chain: Vec<GoSourceAnchor>,
    },
    Unknown {
        reason: GoDeclaredTypeUnknown,
        syntax: GoSourceTypeNode,
        declaration_chain: Vec<GoSourceAnchor>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoDeclaredTypeShape {
    Struct {
        fields: Vec<GoStructFieldIdentity>,
        declaration_chain: Vec<GoSourceAnchor>,
    },
    Function(GoFunctionTypeShape),
    Other {
        syntax_kind: String,
        syntax: GoSourceTypeNode,
        declaration_chain: Vec<GoSourceAnchor>,
    },
    Unknown {
        reason: GoDeclaredTypeUnknown,
        syntax: GoSourceTypeNode,
        declaration_chain: Vec<GoSourceAnchor>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSourceDeclarationIdentity {
    pub artifact_sha256: String,
    pub package_import_path: String,
    pub anchor: GoSourceAnchor,
    /// Exact declaration name from its AST name node. Function literals have
    /// no declaration name and keep this as `None`.
    pub name: Option<GoSourceName>,
    /// Exact lexical callable anchors, outermost first. Function literals
    /// retain their own node range and never receive a fabricated name.
    pub lexical_owner_chain: Vec<GoSourceAnchor>,
    /// Present only for methods. Unknown remains explicit until the Go
    /// package-scope type resolver can prove this relation.
    pub receiver_type_owner: Option<GoReceiverTypeOwner>,
    /// Present on type declarations and aliases. Struct member ownership and
    /// function parameter/result shape are anchored directly in the parsed AST.
    pub declared_type_shape: Option<GoDeclaredTypeShape>,
    /// Exact signature provenance for named functions, methods, and function
    /// literals. It records AST type nodes and grouped arity; it does not
    /// claim that every type identity is resolved.
    pub callable_signature: Option<GoFunctionTypeShape>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoSourceIdentityGapKind {
    InvalidPackageMetadata,
    EmptyPackageFileSet,
    InvalidRelativePath,
    DuplicatePackageFile,
    AmbiguousArtifactEntry,
    MissingArtifactEntry,
    SelectedBytesOverBudget,
    InvalidUtf8,
    ParserUnavailable,
    ParseError,
    PackageNameMismatch,
    InvalidAstRange,
    ReceiverOwnerUnknown,
    ReceiverSyntaxUnavailable,
    CallableSignatureUnknown,
    Cancelled,
    NodeBudgetExhausted,
    DeclaredTypeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSourceIdentityGap {
    pub kind: GoSourceIdentityGapKind,
    pub file: Option<String>,
    pub byte_range: Option<GoSourceByteRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSourceIdentityAnalysis {
    pub artifact_sha256: String,
    pub package_import_path: String,
    pub identities: Vec<GoSourceDeclarationIdentity>,
    pub gaps: Vec<GoSourceIdentityGap>,
    pub visited_nodes: usize,
}

impl From<GoSourceByteRange> for SourceByteRange {
    fn from(range: GoSourceByteRange) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

impl From<SourceByteRange> for GoSourceByteRange {
    fn from(range: SourceByteRange) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

impl From<&GoSourceAnchor> for SourceAnchor {
    fn from(anchor: &GoSourceAnchor) -> Self {
        Self {
            file: anchor.file.clone(),
            byte_range: anchor.byte_range.into(),
            kind: match anchor.kind {
                GoSourceDeclarationKind::Function => SourceDeclarationKind::Function,
                GoSourceDeclarationKind::Method => SourceDeclarationKind::Method,
                GoSourceDeclarationKind::FunctionLiteral => SourceDeclarationKind::FunctionLiteral,
                GoSourceDeclarationKind::Type => SourceDeclarationKind::Type,
                GoSourceDeclarationKind::TypeAlias => SourceDeclarationKind::TypeAlias,
                GoSourceDeclarationKind::StructField => SourceDeclarationKind::StructField,
            },
        }
    }
}

impl From<&GoSourceTypeNode> for SourceTypeNode {
    fn from(node: &GoSourceTypeNode) -> Self {
        Self {
            file: node.file.clone(),
            byte_range: node.byte_range.into(),
        }
    }
}

impl From<&GoFunctionParameterShape> for SourceParameterShape {
    fn from(parameter: &GoFunctionParameterShape) -> Self {
        Self {
            type_node: (&parameter.type_node).into(),
            variadic: parameter.variadic,
            arity: parameter.arity,
        }
    }
}

impl From<&GoFunctionTypeShape> for SourceCallableShape {
    fn from(shape: &GoFunctionTypeShape) -> Self {
        Self {
            function_type: (&shape.function_type).into(),
            parameters: shape.parameters.iter().map(Into::into).collect(),
            results: shape.results.iter().map(Into::into).collect(),
            declaration_chain: shape.declaration_chain.iter().map(Into::into).collect(),
        }
    }
}

impl GoSourceDeclarationIdentity {
    /// Convert a freshly discovered Go function literal to the neutral native
    /// transport. This retains only exact AST anchors and does not resolve the
    /// signature's semantic type identities.
    pub fn anonymous_callable_identity(
        &self,
        id: impl Into<String>,
    ) -> Option<AnonymousCallableIdentity> {
        if self.anchor.kind != GoSourceDeclarationKind::FunctionLiteral {
            return None;
        }
        Some(AnonymousCallableIdentity {
            id: id.into(),
            artifact_sha256: self.artifact_sha256.clone(),
            package_identity: self.package_import_path.clone(),
            anchor: (&self.anchor).into(),
            lexical_owner_chain: self.lexical_owner_chain.iter().map(Into::into).collect(),
            signature: self.callable_signature.as_ref()?.into(),
        })
    }
}

/// An anonymous callable ID paired with a source identity freshly rebound to
/// the exact artifact and pinned package. This value is query evidence only;
/// it does not resolve any parameter or result type identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBoundAnonymousCallableIdentity {
    id: String,
    source: GoSourceDeclarationIdentity,
    visited_nodes: usize,
}

impl GoBoundAnonymousCallableIdentity {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn source(&self) -> &GoSourceDeclarationIdentity {
        &self.source
    }

    pub const fn visited_nodes(&self) -> usize {
        self.visited_nodes
    }
}

/// Why an authored anonymous-callable identity could not be rebound to the
/// exact pinned Go package source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoAnonymousCallableIdentityBindingError {
    ArtifactMismatch,
    PackageMismatch,
    Cancelled {
        visited_nodes: usize,
    },
    NodeBudgetExhausted {
        max_nodes: usize,
        visited_nodes: usize,
    },
    SourceDiscoveryIncomplete {
        visited_nodes: usize,
    },
    IdentityNotFound {
        visited_nodes: usize,
    },
    AmbiguousIdentity {
        visited_nodes: usize,
    },
}

impl GoAnonymousCallableIdentityBindingError {
    pub const fn visited_nodes(self) -> usize {
        match self {
            Self::ArtifactMismatch | Self::PackageMismatch => 0,
            Self::Cancelled { visited_nodes }
            | Self::SourceDiscoveryIncomplete { visited_nodes }
            | Self::IdentityNotFound { visited_nodes }
            | Self::AmbiguousIdentity { visited_nodes }
            | Self::NodeBudgetExhausted { visited_nodes, .. } => visited_nodes,
        }
    }
}

/// Why a catalog returned-callable target could not be rebound to exact Go source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoCatalogAnonymousCallableBindingError {
    MissingAnonymousTarget,
    TargetMismatch,
    Source(GoAnonymousCallableIdentityBindingError),
}

/// Rebind a SQL result's anonymous target to a fresh AST of its exact artifact.
/// The catalog result is the language-neutral query seam; Go validates the target
/// ID and binds the retained structural identity to the current package AST.
/// Success proves declaration identity, not invocation or coverage. This helper
/// does not establish activation; callers must use an activated query first.
pub fn bind_catalog_go_anonymous_callable_target(
    fact: &CatalogCallableValueFact,
    artifact: &ExactArtifact,
    package: &GoPinnedPackage,
    max_nodes: usize,
    cancellation: &CancellationToken,
) -> Result<GoBoundAnonymousCallableIdentity, GoCatalogAnonymousCallableBindingError> {
    let identity = fact
        .anonymous_callable
        .as_ref()
        .ok_or(GoCatalogAnonymousCallableBindingError::MissingAnonymousTarget)?;
    if !matches!(&fact.fact.payload,
        CsmiCallableValuesPayload::ReturnedCallable { target, .. } if target == &identity.id)
    {
        return Err(GoCatalogAnonymousCallableBindingError::TargetMismatch);
    }
    bind_go_anonymous_callable_identity(artifact, package, identity, max_nodes, Some(cancellation))
        .map_err(GoCatalogAnonymousCallableBindingError::Source)
}

impl GoSourceIdentityAnalysis {
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Whether every selected source entry was parsed and the declaration walk
    /// completed. Per-declaration semantic gaps, such as unresolved method
    /// receivers or unrelated named-type identities, do not make literal
    /// anchor discovery incomplete.
    pub fn is_source_discovery_complete(&self) -> bool {
        !self.gaps.iter().any(|gap| {
            !matches!(
                gap.kind,
                GoSourceIdentityGapKind::ReceiverOwnerUnknown
                    | GoSourceIdentityGapKind::ReceiverSyntaxUnavailable
                    | GoSourceIdentityGapKind::CallableSignatureUnknown
                    | GoSourceIdentityGapKind::DeclaredTypeUnknown
            )
        })
    }
}

/// Reparse the exact acquired artifact and bind one authored anonymous-callable
/// descriptor to the current AST. The descriptor itself is untrusted wire data;
/// matching its digest, package, literal anchor, lexical owners, and full
/// signature against a complete fresh analysis is what makes the returned
/// source identity usable by a caller.
pub fn bind_go_anonymous_callable_identity(
    artifact: &ExactArtifact,
    package: &GoPinnedPackage,
    identity: &AnonymousCallableIdentity,
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<GoBoundAnonymousCallableIdentity, GoAnonymousCallableIdentityBindingError> {
    if identity.artifact_sha256 != artifact.sha256() {
        return Err(GoAnonymousCallableIdentityBindingError::ArtifactMismatch);
    }
    if identity.package_identity != package.import_path {
        return Err(GoAnonymousCallableIdentityBindingError::PackageMismatch);
    }

    let analysis = analyze_go_package_source_identities(artifact, package, max_nodes, cancellation);
    let visited_nodes = analysis.visited_nodes;
    if !analysis.is_source_discovery_complete() {
        if analysis
            .gaps
            .iter()
            .any(|gap| gap.kind == GoSourceIdentityGapKind::Cancelled)
        {
            return Err(GoAnonymousCallableIdentityBindingError::Cancelled { visited_nodes });
        }
        if analysis
            .gaps
            .iter()
            .any(|gap| gap.kind == GoSourceIdentityGapKind::NodeBudgetExhausted)
        {
            return Err(
                GoAnonymousCallableIdentityBindingError::NodeBudgetExhausted {
                    max_nodes,
                    visited_nodes,
                },
            );
        }
        return Err(
            GoAnonymousCallableIdentityBindingError::SourceDiscoveryIncomplete { visited_nodes },
        );
    }
    if analysis.gaps.iter().any(|gap| {
        gap.kind == GoSourceIdentityGapKind::CallableSignatureUnknown
            && gap.file.as_deref() == Some(identity.anchor.file.as_str())
            && gap.byte_range == Some(identity.anchor.byte_range.into())
    }) {
        return Err(
            GoAnonymousCallableIdentityBindingError::SourceDiscoveryIncomplete { visited_nodes },
        );
    }
    let mut matches = analysis.identities.into_iter().filter(|candidate| {
        candidate.artifact_sha256 == identity.artifact_sha256
            && candidate.package_import_path == identity.package_identity
            && SourceAnchor::from(&candidate.anchor) == identity.anchor
            && candidate.anchor.kind == GoSourceDeclarationKind::FunctionLiteral
            && candidate
                .lexical_owner_chain
                .iter()
                .map(SourceAnchor::from)
                .collect::<Vec<_>>()
                == identity.lexical_owner_chain
            && candidate
                .callable_signature
                .as_ref()
                .map(SourceCallableShape::from)
                .as_ref()
                == Some(&identity.signature)
    });
    let Some(bound) = matches.next() else {
        return Err(GoAnonymousCallableIdentityBindingError::IdentityNotFound { visited_nodes });
    };
    if matches.next().is_some() {
        return Err(GoAnonymousCallableIdentityBindingError::AmbiguousIdentity { visited_nodes });
    }
    Ok(GoBoundAnonymousCallableIdentity {
        id: identity.id.clone(),
        source: bound,
        visited_nodes: analysis.visited_nodes,
    })
}

/// Rebind an anonymous identity while demanding only its selected source file.
///
/// Package acquisition still has to prove that the selected file belongs to
/// the pinned package. This helper deliberately does not require unrelated
/// package files to be present in the exact source set, so a demand-scoped
/// artifact can materialize one selected body without turning an unrelated
/// package gap into an executable result.
pub fn bind_go_anonymous_callable_identity_in_selected_file(
    artifact: &ExactArtifact,
    package: &GoPinnedPackage,
    identity: &AnonymousCallableIdentity,
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<GoBoundAnonymousCallableIdentity, GoAnonymousCallableIdentityBindingError> {
    let selected_file = identity.anchor.file.as_str();
    let selected_count = package
        .files
        .iter()
        .filter(|file| file.as_str() == selected_file)
        .count();
    if selected_count == 0 {
        return Err(GoAnonymousCallableIdentityBindingError::IdentityNotFound { visited_nodes: 0 });
    }
    if selected_count != 1 {
        return Err(
            GoAnonymousCallableIdentityBindingError::SourceDiscoveryIncomplete { visited_nodes: 0 },
        );
    }
    let selected_package = GoPinnedPackage {
        import_path: package.import_path.clone(),
        name: package.name.clone(),
        files: vec![identity.anchor.file.clone()],
    };
    bind_go_anonymous_callable_identity(
        artifact,
        &selected_package,
        identity,
        max_nodes,
        cancellation,
    )
}

struct ParsedSource<'a> {
    file: &'a str,
    source: &'a str,
    tree: Tree,
}

struct PackageTypeBinding<'tree, 'source> {
    anchor: GoSourceAnchor,
    type_node: Node<'tree>,
    source: &'source str,
}

enum WalkEvent<'tree> {
    Enter(Node<'tree>),
    ExitCallable,
}

/// Extract AST declaration anchors from the files explicitly listed by one
/// pinned package. `max_nodes` bounds the iterative AST walk across all of its
/// selected files; parsing itself observes `cancellation` through the shared
/// Go parser. A nonempty `gaps` list makes the result incomplete.
pub fn analyze_go_package_source_identities(
    artifact: &ExactArtifact,
    package: &GoPinnedPackage,
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> GoSourceIdentityAnalysis {
    let mut result = GoSourceIdentityAnalysis {
        artifact_sha256: artifact.sha256().to_owned(),
        package_import_path: package.import_path.clone(),
        identities: Vec::new(),
        gaps: Vec::new(),
        visited_nodes: 0,
    };
    let mut gap = |kind, file: Option<String>, byte_range| {
        result.gaps.push(GoSourceIdentityGap {
            kind,
            file,
            byte_range,
        });
    };

    if package.import_path.is_empty() || package.name.is_empty() {
        gap(GoSourceIdentityGapKind::InvalidPackageMetadata, None, None);
        return result;
    }
    if package.files.is_empty() {
        gap(GoSourceIdentityGapKind::EmptyPackageFileSet, None, None);
        return result;
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        gap(GoSourceIdentityGapKind::Cancelled, None, None);
        return result;
    }

    if max_nodes == 0 {
        gap(GoSourceIdentityGapKind::NodeBudgetExhausted, None, None);
        return result;
    }
    let mut entries: HashMap<&str, Vec<&[u8]>> = HashMap::new();
    for (index, entry) in artifact.source_entries().iter().enumerate() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            gap(GoSourceIdentityGapKind::Cancelled, None, None);
            return result;
        }
        if index >= max_nodes {
            gap(GoSourceIdentityGapKind::NodeBudgetExhausted, None, None);
            return result;
        }
        entries
            .entry(entry.relative_path())
            .or_default()
            .push(entry.bytes());
    }

    let mut selected = HashSet::new();
    let mut parsed = Vec::new();
    let mut selected_bytes = 0u64;
    for file in &package.files {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            gap(GoSourceIdentityGapKind::Cancelled, Some(file.clone()), None);
            break;
        }
        if !portable_module_path(file) {
            gap(
                GoSourceIdentityGapKind::InvalidRelativePath,
                Some(file.clone()),
                None,
            );
            continue;
        }
        if !selected.insert(file.as_str()) {
            gap(
                GoSourceIdentityGapKind::DuplicatePackageFile,
                Some(file.clone()),
                None,
            );
            continue;
        }
        let Some(matches) = entries.get(file.as_str()) else {
            gap(
                GoSourceIdentityGapKind::MissingArtifactEntry,
                Some(file.clone()),
                None,
            );
            continue;
        };
        let [bytes] = matches.as_slice() else {
            gap(
                GoSourceIdentityGapKind::AmbiguousArtifactEntry,
                Some(file.clone()),
                None,
            );
            continue;
        };
        selected_bytes = selected_bytes.saturating_add(bytes.len() as u64);
        if selected_bytes > ArtifactProducerLimits::default().max_artifact_bytes {
            gap(
                GoSourceIdentityGapKind::SelectedBytesOverBudget,
                Some(file.clone()),
                None,
            );
            break;
        }
        let source = match std::str::from_utf8(bytes) {
            Ok(source) => source,
            Err(_) => {
                gap(
                    GoSourceIdentityGapKind::InvalidUtf8,
                    Some(file.clone()),
                    None,
                );
                continue;
            }
        };
        let Some(tree) = parse_go_with_cancellation(source, cancellation) else {
            let kind = if cancellation.is_some_and(CancellationToken::is_cancelled) {
                GoSourceIdentityGapKind::Cancelled
            } else {
                GoSourceIdentityGapKind::ParserUnavailable
            };
            gap(kind, Some(file.clone()), None);
            if kind == GoSourceIdentityGapKind::Cancelled {
                break;
            }
            continue;
        };
        if tree.root_node().has_error() {
            gap(
                GoSourceIdentityGapKind::ParseError,
                Some(file.clone()),
                None,
            );
            continue;
        }
        let package_clauses = {
            let mut cursor = tree.root_node().walk();
            tree.root_node()
                .named_children(&mut cursor)
                .filter(|node| node.kind() == "package_clause")
                .count()
        };
        if package_clauses != 1
            || determine_go_package_name(tree.root_node(), source) != package.name
        {
            gap(
                GoSourceIdentityGapKind::PackageNameMismatch,
                Some(file.clone()),
                None,
            );
            continue;
        }
        parsed.push(ParsedSource { file, source, tree });
    }

    // Only direct declarations in each package file participate in Go's
    // package block. Local declarations, imports, and same-spelled names in
    // other scopes are intentionally absent from this index.
    let mut package_types = HashMap::<String, Vec<PackageTypeBinding<'_, '_>>>::new();
    for parsed_source in &parsed {
        let mut remaining = max_nodes.saturating_sub(result.visited_nodes);
        let declarations =
            match shape_children(parsed_source.tree.root_node(), &mut remaining, cancellation) {
                Ok(children) => children,
                Err(reason) => {
                    gap(
                        if reason == GoDeclaredTypeUnknown::Cancelled {
                            GoSourceIdentityGapKind::Cancelled
                        } else {
                            GoSourceIdentityGapKind::NodeBudgetExhausted
                        },
                        Some(parsed_source.file.to_owned()),
                        None,
                    );
                    return result;
                }
            };
        result.visited_nodes = max_nodes - remaining;
        for declaration in declarations
            .into_iter()
            .filter(|node| node.kind() == "type_declaration")
        {
            let mut remaining = max_nodes.saturating_sub(result.visited_nodes);
            let specs = match shape_children(declaration, &mut remaining, cancellation) {
                Ok(children) => children,
                Err(reason) => {
                    gap(
                        if reason == GoDeclaredTypeUnknown::Cancelled {
                            GoSourceIdentityGapKind::Cancelled
                        } else {
                            GoSourceIdentityGapKind::NodeBudgetExhausted
                        },
                        Some(parsed_source.file.to_owned()),
                        None,
                    );
                    return result;
                }
            };
            result.visited_nodes = max_nodes - remaining;
            for spec in specs
                .into_iter()
                .filter(|node| matches!(node.kind(), "type_spec" | "type_alias"))
            {
                if result.visited_nodes >= max_nodes {
                    gap(
                        GoSourceIdentityGapKind::NodeBudgetExhausted,
                        Some(parsed_source.file.to_owned()),
                        None,
                    );
                    break;
                }
                result.visited_nodes += 1;
                let (Some(name_node), Some(type_node), Some(kind)) = (
                    spec.child_by_field_name("name"),
                    spec.child_by_field_name("type"),
                    declaration_kind(spec.kind()),
                ) else {
                    continue;
                };
                let Some(anchor) =
                    source_anchor(parsed_source.file, spec, kind, parsed_source.source.len())
                else {
                    continue;
                };
                let Some(name) = node_text(parsed_source.source, name_node) else {
                    continue;
                };
                package_types
                    .entry(name)
                    .or_default()
                    .push(PackageTypeBinding {
                        anchor,
                        type_node,
                        source: parsed_source.source,
                    });
            }
        }
    }

    let mut stop = false;
    for parsed_source in &parsed {
        let root = parsed_source.tree.root_node();
        let mut events = vec![WalkEvent::Enter(root)];
        let mut lexical_owners = Vec::new();
        while let Some(event) = events.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                gap(
                    GoSourceIdentityGapKind::Cancelled,
                    Some(parsed_source.file.to_owned()),
                    None,
                );
                stop = true;
                break;
            }
            match event {
                WalkEvent::ExitCallable => {
                    lexical_owners.pop();
                }
                WalkEvent::Enter(node) => {
                    if result.visited_nodes >= max_nodes {
                        gap(
                            GoSourceIdentityGapKind::NodeBudgetExhausted,
                            Some(parsed_source.file.to_owned()),
                            None,
                        );
                        stop = true;
                        break;
                    }
                    result.visited_nodes += 1;
                    let Some(kind) = declaration_kind(node.kind()) else {
                        push_named_children(node, &mut events);
                        continue;
                    };
                    let Some(anchor) =
                        source_anchor(parsed_source.file, node, kind, parsed_source.source.len())
                    else {
                        gap(
                            GoSourceIdentityGapKind::InvalidAstRange,
                            Some(parsed_source.file.to_owned()),
                            Some(GoSourceByteRange {
                                start: node.start_byte(),
                                end: node.end_byte(),
                            }),
                        );
                        push_named_children(node, &mut events);
                        continue;
                    };

                    let receiver_type_owner = if kind == GoSourceDeclarationKind::Method {
                        match go_method_receiver_type_node(node) {
                            Some(receiver) if generic_receiver_base(receiver).is_some() => {
                                let base = generic_receiver_base(receiver)
                                    .expect("generic receiver has a base type");
                                let owner = node_text(parsed_source.source, base)
                                    .and_then(|name| package_types.get(&name));
                                match owner.map(Vec::as_slice) {
                                    Some([binding]) => {
                                        Some(GoReceiverTypeOwner::Exact(binding.anchor.clone()))
                                    }
                                    _ => {
                                        gap(
                                            GoSourceIdentityGapKind::ReceiverOwnerUnknown,
                                            Some(parsed_source.file.to_owned()),
                                            Some(GoSourceByteRange {
                                                start: receiver.start_byte(),
                                                end: receiver.end_byte(),
                                            }),
                                        );
                                        Some(GoReceiverTypeOwner::Unknown {
                                            reason:
                                                GoReceiverOwnerUnknown::TypeResolutionUnavailable,
                                            syntax_range: Some(GoSourceByteRange {
                                                start: receiver.start_byte(),
                                                end: receiver.end_byte(),
                                            }),
                                        })
                                    }
                                }
                            }
                            Some(receiver) => {
                                gap(
                                    GoSourceIdentityGapKind::ReceiverOwnerUnknown,
                                    Some(parsed_source.file.to_owned()),
                                    Some(GoSourceByteRange {
                                        start: receiver.start_byte(),
                                        end: receiver.end_byte(),
                                    }),
                                );
                                Some(GoReceiverTypeOwner::Unknown {
                                    reason: GoReceiverOwnerUnknown::TypeResolutionUnavailable,
                                    syntax_range: Some(GoSourceByteRange {
                                        start: receiver.start_byte(),
                                        end: receiver.end_byte(),
                                    }),
                                })
                            }
                            None => {
                                gap(
                                    GoSourceIdentityGapKind::ReceiverSyntaxUnavailable,
                                    Some(parsed_source.file.to_owned()),
                                    Some(anchor.byte_range),
                                );
                                Some(GoReceiverTypeOwner::Unknown {
                                    reason: GoReceiverOwnerUnknown::ReceiverSyntaxUnavailable,
                                    syntax_range: None,
                                })
                            }
                        }
                    } else {
                        None
                    };
                    let declared_type_shape = if matches!(
                        kind,
                        GoSourceDeclarationKind::Type | GoSourceDeclarationKind::TypeAlias
                    ) {
                        let Some(type_node) = node.child_by_field_name("type") else {
                            gap(
                                GoSourceIdentityGapKind::DeclaredTypeUnknown,
                                Some(parsed_source.file.to_owned()),
                                Some(anchor.byte_range),
                            );
                            result.identities.push(GoSourceDeclarationIdentity {
                                artifact_sha256: result.artifact_sha256.clone(),
                                package_import_path: package.import_path.clone(),
                                anchor: anchor.clone(),
                                lexical_owner_chain: lexical_owners.clone(),
                                receiver_type_owner,
                                name: declaration_name(node, parsed_source.source),
                                declared_type_shape: None,
                                callable_signature: None,
                            });
                            push_named_children(node, &mut events);
                            continue;
                        };
                        let remaining = max_nodes.saturating_sub(result.visited_nodes);
                        let (shape, used) = if !lexical_owners.is_empty() {
                            (
                                GoDeclaredTypeShape::Unknown {
                                    reason: GoDeclaredTypeUnknown::UnsupportedTypeSyntax,
                                    syntax: type_node_location(parsed_source.file, type_node),
                                    declaration_chain: vec![anchor.clone()],
                                },
                                0,
                            )
                        } else if declaration_name(node, parsed_source.source).is_some_and(|name| {
                            package_types
                                .get(&name.text)
                                .is_some_and(|bindings| bindings.len() != 1)
                        }) {
                            (
                                GoDeclaredTypeShape::Unknown {
                                    reason: GoDeclaredTypeUnknown::AmbiguousPackageType,
                                    syntax: type_node_location(parsed_source.file, type_node),
                                    declaration_chain: vec![anchor.clone()],
                                },
                                0,
                            )
                        } else {
                            resolve_declared_type_shape(
                                parsed_source.file,
                                parsed_source.source,
                                type_node,
                                &anchor,
                                &package_types,
                                remaining,
                                cancellation,
                            )
                        };
                        result.visited_nodes = result.visited_nodes.saturating_add(used);
                        let unknown_reason =
                            match &shape {
                                GoDeclaredTypeShape::Unknown { reason, .. } => Some(*reason),
                                GoDeclaredTypeShape::Struct { fields, .. } => fields
                                    .iter()
                                    .find_map(|field| match &field.outer_type_shape {
                                        GoOuterTypeShape::Unknown { reason, .. } => Some(*reason),
                                        _ => None,
                                    }),
                                _ => None,
                            };
                        if let Some(reason) = unknown_reason {
                            gap(
                                match reason {
                                    GoDeclaredTypeUnknown::NodeBudgetExhausted => {
                                        GoSourceIdentityGapKind::NodeBudgetExhausted
                                    }
                                    GoDeclaredTypeUnknown::Cancelled => {
                                        GoSourceIdentityGapKind::Cancelled
                                    }
                                    _ => GoSourceIdentityGapKind::DeclaredTypeUnknown,
                                },
                                Some(parsed_source.file.to_owned()),
                                Some(type_node_range(type_node)),
                            );
                        }
                        Some(shape)
                    } else {
                        None
                    };
                    let callable_signature = if matches!(
                        kind,
                        GoSourceDeclarationKind::Function
                            | GoSourceDeclarationKind::Method
                            | GoSourceDeclarationKind::FunctionLiteral
                    ) {
                        let remaining = max_nodes.saturating_sub(result.visited_nodes);
                        match callable_signature_shape(
                            parsed_source.file,
                            node,
                            &[],
                            remaining,
                            cancellation,
                        ) {
                            Ok((shape, used)) => {
                                result.visited_nodes = result.visited_nodes.saturating_add(used);
                                Some(shape)
                            }
                            Err(reason) => {
                                let gap_kind = match reason {
                                    GoDeclaredTypeUnknown::NodeBudgetExhausted => {
                                        GoSourceIdentityGapKind::NodeBudgetExhausted
                                    }
                                    GoDeclaredTypeUnknown::Cancelled => {
                                        GoSourceIdentityGapKind::Cancelled
                                    }
                                    _ => GoSourceIdentityGapKind::CallableSignatureUnknown,
                                };
                                gap(
                                    gap_kind,
                                    Some(parsed_source.file.to_owned()),
                                    Some(anchor.byte_range),
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    result.identities.push(GoSourceDeclarationIdentity {
                        artifact_sha256: result.artifact_sha256.clone(),
                        package_import_path: package.import_path.clone(),
                        anchor: anchor.clone(),
                        name: declaration_name(node, parsed_source.source),
                        lexical_owner_chain: lexical_owners.clone(),
                        receiver_type_owner,
                        declared_type_shape,
                        callable_signature,
                    });

                    let callable = matches!(
                        kind,
                        GoSourceDeclarationKind::Function
                            | GoSourceDeclarationKind::Method
                            | GoSourceDeclarationKind::FunctionLiteral
                    );
                    if callable {
                        lexical_owners.push(anchor);
                        events.push(WalkEvent::ExitCallable);
                    }
                    push_named_children(node, &mut events);
                }
            }
        }
        if stop {
            break;
        }
    }
    result
}

fn portable_module_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\0')
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value
            .as_bytes()
            .get(0..2)
            .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
        && is_canonical_relative_path(value)
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn declaration_kind(kind: &str) -> Option<GoSourceDeclarationKind> {
    match kind {
        "function_declaration" => Some(GoSourceDeclarationKind::Function),
        "method_declaration" => Some(GoSourceDeclarationKind::Method),
        "func_literal" => Some(GoSourceDeclarationKind::FunctionLiteral),
        "type_spec" => Some(GoSourceDeclarationKind::Type),
        "type_alias" => Some(GoSourceDeclarationKind::TypeAlias),
        _ => None,
    }
}

fn declaration_name(node: Node<'_>, source: &str) -> Option<GoSourceName> {
    let name = node.child_by_field_name("name")?;
    Some(GoSourceName {
        text: node_text(source, name)?,
        byte_range: type_node_range(name),
    })
}

fn node_text(source: &str, node: Node<'_>) -> Option<String> {
    source
        .get(node.start_byte()..node.end_byte())
        .map(str::to_owned)
}

fn type_node_range(node: Node<'_>) -> GoSourceByteRange {
    GoSourceByteRange {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}

fn type_node_location(file: &str, node: Node<'_>) -> GoSourceTypeNode {
    GoSourceTypeNode {
        file: file.to_owned(),
        byte_range: type_node_range(node),
    }
}

fn is_variadic_parameter(node: Node<'_>) -> bool {
    node.kind() == "variadic_parameter_declaration"
}

/// Follow named package bindings without expanding nested struct fields.
fn resolve_outer_type_shape(
    file: &str,
    source: &str,
    initial: Node<'_>,
    chain: Vec<GoSourceAnchor>,
    package_types: &HashMap<String, Vec<PackageTypeBinding<'_, '_>>>,
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> GoOuterTypeShape {
    let mut node = initial;
    let mut source = source;
    let mut file = file;
    let mut chain = chain;
    let mut visited = HashSet::new();
    loop {
        if let Err(reason) = shape_step(remaining, cancellation) {
            return GoOuterTypeShape::Unknown {
                reason,
                syntax: type_node_location(file, node),
                declaration_chain: chain,
            };
        }
        if node.kind() == "generic_type" {
            let Some(base) = node.child_by_field_name("type") else {
                return GoOuterTypeShape::Unknown {
                    reason: GoDeclaredTypeUnknown::InvalidAstShape,
                    syntax: type_node_location(file, node),
                    declaration_chain: chain,
                };
            };
            node = base;
            continue;
        }
        if matches!(node.kind(), "type_identifier" | "identifier") {
            let Some(name) = node_text(source, node) else {
                return GoOuterTypeShape::Unknown {
                    reason: GoDeclaredTypeUnknown::InvalidAstShape,
                    syntax: type_node_location(file, node),
                    declaration_chain: chain,
                };
            };
            if is_go_type_parameter_reference(node, source, &name) {
                return GoOuterTypeShape::Other {
                    syntax_kind: "type_parameter".to_owned(),
                    syntax: type_node_location(file, node),
                    declaration_chain: chain,
                };
            }
            if !visited.insert(name.clone()) {
                return GoOuterTypeShape::Unknown {
                    reason: GoDeclaredTypeUnknown::TypeCycle,
                    syntax: type_node_location(file, node),
                    declaration_chain: chain,
                };
            }
            match package_types.get(&name).map(Vec::as_slice) {
                Some([binding]) => {
                    chain.push(binding.anchor.clone());
                    node = binding.type_node;
                    source = binding.source;
                    file = &binding.anchor.file;
                    continue;
                }
                Some(_) => {
                    return GoOuterTypeShape::Unknown {
                        reason: GoDeclaredTypeUnknown::AmbiguousPackageType,
                        syntax: type_node_location(file, node),
                        declaration_chain: chain,
                    };
                }
                None if is_predeclared_go_type(&name) => {}
                None => {
                    return GoOuterTypeShape::Unknown {
                        reason: GoDeclaredTypeUnknown::UnresolvedPackageType,
                        syntax: type_node_location(file, node),
                        declaration_chain: chain,
                    };
                }
            }
        }
        if node.kind() == "function_type" {
            return match function_type_shape(file, node, &chain, remaining, cancellation) {
                Ok(shape) => GoOuterTypeShape::Function(shape),
                Err(reason) => GoOuterTypeShape::Unknown {
                    reason,
                    syntax: type_node_location(file, node),
                    declaration_chain: chain,
                },
            };
        }
        return GoOuterTypeShape::Other {
            syntax_kind: node.kind().to_owned(),
            syntax: type_node_location(file, node),
            declaration_chain: chain,
        };
    }
}

fn shape_step(
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(), GoDeclaredTypeUnknown> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(GoDeclaredTypeUnknown::Cancelled);
    }
    *remaining = remaining
        .checked_sub(1)
        .ok_or(GoDeclaredTypeUnknown::NodeBudgetExhausted)?;
    Ok(())
}

fn shape_children<'a>(
    node: Node<'a>,
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Node<'a>>, GoDeclaredTypeUnknown> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    for child in node.named_children(&mut cursor) {
        shape_step(remaining, cancellation)?;
        children.push(child);
    }
    Ok(children)
}

fn function_type_shape(
    file: &str,
    node: Node<'_>,
    chain: &[GoSourceAnchor],
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<GoFunctionTypeShape, GoDeclaredTypeUnknown> {
    let (parameters, results) =
        function_parameter_result_shapes(file, node, remaining, cancellation)?;
    Ok(GoFunctionTypeShape {
        function_type: type_node_location(file, node),
        parameters,
        results,
        declaration_chain: chain.to_vec(),
    })
}

fn function_parameter_result_shapes(
    file: &str,
    node: Node<'_>,
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(Vec<GoFunctionParameterShape>, Vec<GoFunctionParameterShape>), GoDeclaredTypeUnknown> {
    let parameters = node
        .child_by_field_name("parameters")
        .ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?;
    let parameters = function_parameter_shapes(file, parameters, remaining, cancellation)?;
    let results = match node.child_by_field_name("result") {
        Some(result) if result.kind() == "parameter_list" => {
            function_parameter_shapes(file, result, remaining, cancellation)?
        }
        Some(result) => vec![GoFunctionParameterShape {
            type_node: type_node_location(file, result),
            variadic: false,
            arity: 1,
        }],
        None => Vec::new(),
    };
    Ok((parameters, results))
}

fn function_literal_signature_shape(
    file: &str,
    node: Node<'_>,
    chain: &[GoSourceAnchor],
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(GoFunctionTypeShape, usize), GoDeclaredTypeUnknown> {
    let body = node
        .child_by_field_name("body")
        .ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?;
    let mut remaining = max_nodes;
    let mut shape = function_type_shape(file, node, chain, &mut remaining, cancellation)?;
    let signature_end = body.start_byte();
    if signature_end <= node.start_byte() || signature_end > node.end_byte() {
        return Err(GoDeclaredTypeUnknown::InvalidAstShape);
    }
    // A Go function literal has no separate function_type node. The parser's
    // callable fields define its signature, and the body start is the exact
    // AST boundary after that signature.
    shape.function_type.byte_range = GoSourceByteRange {
        start: node.start_byte(),
        end: signature_end,
    };
    Ok((shape, max_nodes - remaining))
}

fn callable_signature_shape(
    file: &str,
    node: Node<'_>,
    chain: &[GoSourceAnchor],
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(GoFunctionTypeShape, usize), GoDeclaredTypeUnknown> {
    if node.kind() == "func_literal" {
        return function_literal_signature_shape(file, node, chain, max_nodes, cancellation);
    }
    let mut remaining = max_nodes;
    let (parameters, results) =
        function_parameter_result_shapes(file, node, &mut remaining, cancellation)?;
    let signature_end = node
        .child_by_field_name("body")
        .map_or(node.end_byte(), |body| body.start_byte());
    if signature_end <= node.start_byte() || signature_end > node.end_byte() {
        return Err(GoDeclaredTypeUnknown::InvalidAstShape);
    }
    Ok((
        GoFunctionTypeShape {
            function_type: GoSourceTypeNode {
                file: file.to_owned(),
                byte_range: GoSourceByteRange {
                    start: node.start_byte(),
                    end: signature_end,
                },
            },
            parameters,
            results,
            declaration_chain: chain.to_vec(),
        },
        max_nodes - remaining,
    ))
}

fn function_parameter_shapes(
    file: &str,
    list: Node<'_>,
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<GoFunctionParameterShape>, GoDeclaredTypeUnknown> {
    let mut result = Vec::new();
    for parameter in shape_children(list, remaining, cancellation)? {
        if parameter.kind() == "comment" {
            continue;
        }
        if !matches!(
            parameter.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            return Err(GoDeclaredTypeUnknown::InvalidAstShape);
        }
        let ty = parameter
            .child_by_field_name("type")
            .ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?;
        let mut arity = 0;
        let mut cursor = parameter.walk();
        for (index, child) in parameter.children(&mut cursor).enumerate() {
            shape_step(remaining, cancellation)?;
            if child.is_named() && parameter.field_name_for_child(index as u32) == Some("name") {
                arity += 1;
            }
        }
        result.push(GoFunctionParameterShape {
            type_node: type_node_location(file, ty),
            variadic: is_variadic_parameter(parameter),
            arity: arity.max(1),
        });
    }
    Ok(result)
}

fn resolve_declared_type_shape(
    file: &str,
    source: &str,
    initial: Node<'_>,
    owner: &GoSourceAnchor,
    package_types: &HashMap<String, Vec<PackageTypeBinding<'_, '_>>>,
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> (GoDeclaredTypeShape, usize) {
    let mut remaining = max_nodes;
    let outer = resolve_outer_type_shape(
        file,
        source,
        initial,
        vec![owner.clone()],
        package_types,
        &mut remaining,
        cancellation,
    );
    let shape = match outer {
        GoOuterTypeShape::Function(shape) => GoDeclaredTypeShape::Function(shape),
        GoOuterTypeShape::Unknown {
            reason,
            syntax,
            declaration_chain,
        } => GoDeclaredTypeShape::Unknown {
            reason,
            syntax,
            declaration_chain,
        },
        GoOuterTypeShape::Other {
            syntax_kind,
            syntax,
            declaration_chain,
        } if syntax_kind == "struct_type" => {
            let final_owner = declaration_chain
                .last()
                .expect("outer chain begins with declaring type");
            let (struct_node, struct_source) = if final_owner == owner {
                (initial, source)
            } else {
                let mut selected = None;
                for binding in package_types.values().flat_map(|bindings| bindings.iter()) {
                    if let Err(reason) = shape_step(&mut remaining, cancellation) {
                        return (
                            GoDeclaredTypeShape::Unknown {
                                reason,
                                syntax,
                                declaration_chain,
                            },
                            max_nodes - remaining,
                        );
                    }
                    if binding.anchor == *final_owner {
                        selected = Some(binding);
                        break;
                    }
                }
                let binding = selected.expect("outer chain comes from package binder");
                (binding.type_node, binding.source)
            };
            let fields = collect_source_struct_fields(
                &syntax.file,
                struct_source,
                struct_node,
                final_owner,
                package_types,
                &mut remaining,
                cancellation,
            );
            match fields {
                Ok(fields) => GoDeclaredTypeShape::Struct {
                    fields,
                    declaration_chain,
                },
                Err(reason) => GoDeclaredTypeShape::Unknown {
                    reason,
                    syntax,
                    declaration_chain,
                },
            }
        }
        GoOuterTypeShape::Other {
            syntax_kind,
            syntax,
            declaration_chain,
        } => GoDeclaredTypeShape::Other {
            syntax_kind,
            syntax,
            declaration_chain,
        },
    };
    (shape, max_nodes - remaining)
}

fn collect_source_struct_fields(
    file: &str,
    source: &str,
    node: Node<'_>,
    owner: &GoSourceAnchor,
    package_types: &HashMap<String, Vec<PackageTypeBinding<'_, '_>>>,
    remaining: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<GoStructFieldIdentity>, GoDeclaredTypeUnknown> {
    let list = shape_children(node, remaining, cancellation)?
        .into_iter()
        .find(|child| child.kind() == "field_declaration_list")
        .ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?;
    let mut fields = Vec::new();
    for field in shape_children(list, remaining, cancellation)? {
        if field.kind() == "comment" {
            continue;
        }
        if field.kind() != "field_declaration" {
            return Err(GoDeclaredTypeUnknown::InvalidAstShape);
        }
        let ty = field
            .child_by_field_name("type")
            .ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?;
        let mut names = Vec::new();
        let mut cursor = field.walk();
        for child in field.named_children(&mut cursor) {
            shape_step(remaining, cancellation)?;
            if child.kind() == "field_identifier" {
                names.push(GoSourceName {
                    text: node_text(source, child).ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?,
                    byte_range: type_node_range(child),
                });
            }
        }
        let outer_type_shape = resolve_outer_type_shape(
            file,
            source,
            ty,
            Vec::new(),
            package_types,
            remaining,
            cancellation,
        );
        fields.push(GoStructFieldIdentity {
            anchor: source_anchor(
                file,
                field,
                GoSourceDeclarationKind::StructField,
                source.len(),
            )
            .ok_or(GoDeclaredTypeUnknown::InvalidAstShape)?,
            owner: owner.clone(),
            embedded: names.is_empty(),
            name_anchors: names,
            type_node: type_node_location(file, ty),
            outer_type_shape,
        });
    }
    Ok(fields)
}

fn source_anchor(
    file: &str,
    node: Node<'_>,
    kind: GoSourceDeclarationKind,
    source_len: usize,
) -> Option<GoSourceAnchor> {
    let start = node.start_byte();
    let end = node.end_byte();
    (start < end && end <= source_len).then(|| GoSourceAnchor {
        file: file.to_owned(),
        byte_range: GoSourceByteRange { start, end },
        kind,
    })
}

fn generic_receiver_base(receiver: Node<'_>) -> Option<Node<'_>> {
    brokk_bifrost_go::declarations::go_generic_receiver_type(receiver)?.child_by_field_name("type")
}

fn is_go_type_parameter_reference(node: Node<'_>, source: &str, name: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if let Some(parameters) = current.child_by_field_name("type_parameters") {
            let mut cursor = parameters.walk();
            for declaration in parameters.named_children(&mut cursor) {
                if declaration.kind() != "type_parameter_declaration" {
                    continue;
                }
                if children_by_field(declaration, "name")
                    .into_iter()
                    .any(|parameter| node_text(source, parameter).as_deref() == Some(name))
                {
                    return true;
                }
            }
        }
        ancestor = current.parent();
    }
    false
}

fn push_named_children<'tree>(node: Node<'tree>, events: &mut Vec<WalkEvent<'tree>>) {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    events.extend(children.into_iter().rev().map(WalkEvent::Enter));
}

pub trait GoArtifactCallableTarget {
    fn from_bound_go_identity(bound: &GoBoundAnonymousCallableIdentity) -> Self;
}

impl GoArtifactCallableTarget
    for brokk_bifrost_analysis::analyzer::semantic::ArtifactCallableTarget
{
    fn from_bound_go_identity(bound: &GoBoundAnonymousCallableIdentity) -> Self {
        let identity = bound
            .source()
            .anonymous_callable_identity(bound.id())
            .expect("bound anonymous callable has a function-literal signature");
        Self::from_bound_identity(identity)
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::go::source_identity::*;

    use crate::analyzer::go::materialize_go_anonymous_callable;
    use brokk_bifrost_analysis::analyzer::semantic::{ArtifactCallableTarget, CallableTarget};
    use brokk_bifrost_analysis::analyzer::semantic::{
        SemanticBudget, SemanticOutcome, SemanticRequest,
    };

    use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProducerLimits;

    use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_source_set;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn fixture(source: &str) -> (tempfile::TempDir, ExactArtifact, GoPinnedPackage) {
        let directory = tempfile::tempdir().expect("fixture directory");
        let root = directory.path().canonicalize().expect("canonical root");
        let source_path = Path::new("pkg.go");
        fs::write(root.join(source_path), source).expect("fixture source");
        let artifact = read_exact_source_set(
            &root,
            &[PathBuf::from(source_path)],
            1,
            8,
            &ArtifactProducerLimits::default(),
        )
        .expect("exact source set");
        let package = GoPinnedPackage {
            import_path: "example.test/module/pkg".to_owned(),
            name: "pkg".to_owned(),
            files: vec!["pkg.go".to_owned()],
        };
        (directory, artifact, package)
    }

    #[test]
    fn cyclic_local_duplicate_and_unresolved_type_chains_remain_unknown() {
        for source in [
            "package pkg\ntype A = B\ntype B = A\n",
            "package pkg\ntype A = Missing\n",
            "package pkg\ntype A func()\ntype A struct{}\n",
            "package pkg\ntype A func()\nfunc F() { type A int; type B = A; var v B; _ = v }\n",
        ] {
            let (_directory, artifact, package) = fixture(source);
            let result = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
            assert!(!result.is_complete(), "{source}: {result:#?}");
            assert!(result.identities.iter().any(|identity| matches!(
                identity.declared_type_shape,
                Some(GoDeclaredTypeShape::Unknown { .. })
            )));
        }
        let source = "package pkg\ntype T struct { Next T }\n";
        let (_directory, artifact, package) = fixture(source);
        let result = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        assert!(
            result.is_complete(),
            "outer struct must stop without recursive field expansion: {result:#?}"
        );
    }

    #[test]
    fn anonymous_callable_binding_rechecks_exact_ast_despite_unrelated_method_gap() {
        let source = "package pkg\ntype Client struct{}\nfunc (c *Client) Read() {}\nfunc Factory() { _ = func(x int) error { return nil } }\n";
        let (_directory, artifact, package) = fixture(source);
        let analysis = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        assert!(
            !analysis.is_complete(),
            "method receiver remains unresolved"
        );
        assert!(
            analysis.is_source_discovery_complete(),
            "source scan finished"
        );
        let literal = analysis
            .identities
            .iter()
            .find(|identity| identity.anchor.kind == GoSourceDeclarationKind::FunctionLiteral)
            .expect("literal discovered");
        let descriptor = literal
            .anonymous_callable_identity("go.literal.factory.callback")
            .expect("literal has AST-backed signature");
        let bound =
            bind_go_anonymous_callable_identity(&artifact, &package, &descriptor, 10_000, None)
                .expect("unrelated semantic gap does not hide the exact literal");
        assert_eq!(bound.id(), descriptor.id);
        assert_eq!(
            SourceAnchor::from(&bound.source().anchor),
            descriptor.anchor
        );
        assert_eq!(
            bound
                .source()
                .callable_signature
                .as_ref()
                .map(SourceCallableShape::from),
            Some(descriptor.signature.clone())
        );

        let mut wrong_artifact = descriptor.clone();
        wrong_artifact.artifact_sha256 = "0".repeat(64);
        assert_eq!(
            bind_go_anonymous_callable_identity(&artifact, &package, &wrong_artifact, 10_000, None,),
            Err(GoAnonymousCallableIdentityBindingError::ArtifactMismatch)
        );

        let mut wrong_owner = descriptor.clone();
        wrong_owner.lexical_owner_chain[0].byte_range.start += 1;
        assert!(matches!(
            bind_go_anonymous_callable_identity(&artifact, &package, &wrong_owner, 10_000, None,),
            Err(GoAnonymousCallableIdentityBindingError::IdentityNotFound { .. })
        ));

        let mut wrong_range = descriptor.clone();
        wrong_range.anchor.byte_range.end -= 1;
        assert!(matches!(
            bind_go_anonymous_callable_identity(&artifact, &package, &wrong_range, 10_000, None,),
            Err(GoAnonymousCallableIdentityBindingError::IdentityNotFound { .. })
        ));

        let mut wrong_shape = descriptor.clone();
        wrong_shape.signature.parameters[0].arity += 1;
        assert!(matches!(
            bind_go_anonymous_callable_identity(&artifact, &package, &wrong_shape, 10_000, None,),
            Err(GoAnonymousCallableIdentityBindingError::IdentityNotFound { .. })
        ));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            bind_go_anonymous_callable_identity(
                &artifact,
                &package,
                &descriptor,
                10_000,
                Some(&cancelled),
            ),
            Err(GoAnonymousCallableIdentityBindingError::Cancelled { .. })
        ));
        assert!(matches!(
            bind_go_anonymous_callable_identity(&artifact, &package, &descriptor, 1, None),
            Err(GoAnonymousCallableIdentityBindingError::NodeBudgetExhausted { max_nodes: 1, .. })
        ));
        assert!(
            analysis
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::ReceiverOwnerUnknown)
        );
    }

    #[test]
    fn generic_declaration_shape_and_receiver_owner_are_exact() {
        let source = "package pkg\ntype Cache[K comparable, V any] struct { Key K; Value V }\ntype Contract[T any] interface { Accept(value T) }\ntype Handler[T any] struct { Contract[T] }\nfunc (c *Cache[Key, Value]) Get() Value { return c.Value }\n";
        let (_directory, artifact, package) = fixture(source);
        let result = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        let declaration = result
            .identities
            .iter()
            .find(|identity| identity.anchor.kind == GoSourceDeclarationKind::Type)
            .expect("generic type declaration");
        let GoDeclaredTypeShape::Struct { fields, .. } = declaration
            .declared_type_shape
            .as_ref()
            .expect("generic struct shape")
        else {
            panic!("generic struct remains structured: {declaration:#?}");
        };
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().all(|field| matches!(
            field.outer_type_shape,
            GoOuterTypeShape::Other { ref syntax_kind, .. } if syntax_kind == "type_parameter"
        )));
        let handler = result
            .identities
            .iter()
            .find(|identity| {
                identity.anchor.kind == GoSourceDeclarationKind::Type
                    && identity
                        .name
                        .as_ref()
                        .is_some_and(|name| name.text == "Handler")
            })
            .expect("generic embedding owner");
        let GoDeclaredTypeShape::Struct { fields, .. } = handler
            .declared_type_shape
            .as_ref()
            .expect("generic embedding struct shape")
        else {
            panic!("generic embedding owner remains structured: {handler:#?}");
        };
        assert_eq!(fields.len(), 1);
        assert!(matches!(
            fields[0].outer_type_shape,
            GoOuterTypeShape::Other { ref syntax_kind, ref declaration_chain, .. }
                if syntax_kind == "interface_type"
                    && declaration_chain.last().is_some_and(|anchor| anchor.kind == GoSourceDeclarationKind::Type)
        ));
        let method = result
            .identities
            .iter()
            .find(|identity| identity.anchor.kind == GoSourceDeclarationKind::Method)
            .expect("generic receiver method");
        assert_eq!(
            method.receiver_type_owner,
            Some(GoReceiverTypeOwner::Exact(declaration.anchor.clone()))
        );
        assert!(!result.gaps.iter().any(|gap| matches!(
            gap.kind,
            GoSourceIdentityGapKind::ReceiverOwnerUnknown
                | GoSourceIdentityGapKind::DeclaredTypeUnknown
        )));
    }

    #[test]
    fn aliased_import_receiver_does_not_resolve_to_a_local_lookalike() {
        let source = "package pkg\nimport ext \"example.test/dep\"\ntype Client struct{}\nfunc (c *ext.Client) Read() {}\n";
        let (_directory, artifact, package) = fixture(source);
        let result = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        let method = result
            .identities
            .iter()
            .find(|identity| identity.anchor.kind == GoSourceDeclarationKind::Method)
            .expect("method declaration");
        assert!(matches!(
            method.receiver_type_owner,
            Some(GoReceiverTypeOwner::Unknown { .. })
        ));
        assert!(
            result
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::ReceiverOwnerUnknown)
        );
    }

    #[test]
    fn package_mismatch_parse_error_cancellation_and_budget_are_incomplete() {
        let (_directory, artifact, package) = fixture("package other\nfunc F() {}\n");
        let mismatch = analyze_go_package_source_identities(&artifact, &package, 100, None);
        assert!(
            mismatch
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::PackageNameMismatch)
        );

        let (_directory, artifact, package) = fixture("package pkg\nfunc F( {\n");
        let parse_error = analyze_go_package_source_identities(&artifact, &package, 100, None);
        assert!(
            parse_error
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::ParseError)
        );

        let (_directory, artifact, mut package) = fixture("package pkg\nfunc F() {}\n");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled =
            analyze_go_package_source_identities(&artifact, &package, 100, Some(&cancellation));
        assert!(
            cancelled
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::Cancelled)
        );

        let budget = analyze_go_package_source_identities(&artifact, &package, 1, None);
        assert!(
            budget
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::NodeBudgetExhausted)
        );

        package.files.push("missing.go".to_owned());
        let missing = analyze_go_package_source_identities(&artifact, &package, 100, None);
        assert!(
            missing
                .gaps
                .iter()
                .any(|gap| gap.kind == GoSourceIdentityGapKind::MissingArtifactEntry)
        );
    }

    #[test]
    fn selected_file_binding_and_native_artifact_target_keep_exact_identity() {
        let source = "package pkg\nfunc Factory() { _ = func(value int) { _ = value } }\n";
        let (_directory, artifact, mut package) = fixture(source);
        let analysis = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        let literal = analysis
            .identities
            .iter()
            .find(|identity| identity.anchor.kind == GoSourceDeclarationKind::FunctionLiteral)
            .expect("function literal descriptor");
        let descriptor = literal
            .anonymous_callable_identity("go.literal.selected")
            .expect("anonymous identity");

        package.files.push("unavailable.go".to_owned());
        assert!(matches!(
            bind_go_anonymous_callable_identity(&artifact, &package, &descriptor, 10_000, None),
            Err(GoAnonymousCallableIdentityBindingError::SourceDiscoveryIncomplete { .. })
        ));
        let bound = bind_go_anonymous_callable_identity_in_selected_file(
            &artifact,
            &package,
            &descriptor,
            10_000,
            None,
        )
        .expect("unrelated package file is outside the demand scope");

        let target = ArtifactCallableTarget::from_bound_go_identity(&bound);
        assert_eq!(target.identity(), &descriptor);
        let native_target = CallableTarget::Artifact(target);
        assert_eq!(native_target.label(), "artifact");
    }

    #[test]
    fn exact_materialization_returns_same_artifact_factory_and_complete_captures() {
        let source = "package pkg\nfunc Factory() func(int) {\n captured := 7\n return func(value int) { _ = captured; _ = value }\n}\n";
        let (directory, artifact, package) = fixture(source);
        let analysis = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
        let literal = analysis
            .identities
            .iter()
            .find(|identity| identity.anchor.kind == GoSourceDeclarationKind::FunctionLiteral)
            .expect("capturing function literal descriptor");
        let descriptor = literal
            .anonymous_callable_identity("go.literal.materialize")
            .expect("anonymous identity");
        let bound = bind_go_anonymous_callable_identity_in_selected_file(
            &artifact,
            &package,
            &descriptor,
            10_000,
            None,
        )
        .expect("fresh source proof");
        let target = ArtifactCallableTarget::from_bound_go_identity(&bound);
        assert_eq!(target.identity(), &descriptor);

        let root = directory
            .path()
            .canonicalize()
            .expect("canonical fixture root");
        let file = brokk_bifrost_core::analyzer::model::ProjectFile::new(root, "pkg.go");
        let mount =
            brokk_bifrost_analysis::analyzer::semantic::WorkspaceMountId::from_root(file.root());
        let cancellation = CancellationToken::default();
        let mut zero_budget = SemanticBudget::default();
        let stopped = materialize_go_anonymous_callable(
            &file,
            mount,
            &artifact,
            &package,
            &target,
            0,
            &mut SemanticRequest::new(&mut zero_budget, &cancellation),
        )
        .unwrap();
        // A zero-node traversal bound is performed-work telemetry after #5902,
        // so it reports an unknown proof rather than a budget refusal.
        assert!(matches!(
            stopped,
            SemanticOutcome::Unknown { partial: None, .. }
        ));
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let stopped = materialize_go_anonymous_callable(
            &file,
            mount,
            &artifact,
            &package,
            &target,
            10_000,
            &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancelled),
        )
        .unwrap();
        assert!(matches!(stopped, SemanticOutcome::Cancelled { .. }));
        let (_foreign_directory, foreign_artifact, _) = fixture("package pkg\nfunc Other() {}\n");
        let wrong = materialize_go_anonymous_callable(
            &file,
            mount,
            &foreign_artifact,
            &package,
            &target,
            10_000,
            &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
        )
        .unwrap();
        assert!(matches!(
            wrong,
            SemanticOutcome::Unknown { partial: None, .. }
        ));
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let outcome = materialize_go_anonymous_callable(
            &file,
            mount,
            &artifact,
            &package,
            &target,
            10_000,
            &mut request,
        )
        .expect("materializer provider succeeds");
        let materialized = match outcome {
            SemanticOutcome::Complete { value, .. } => value,
            _ => panic!("exact materialization did not complete"),
        };
        assert!(Arc::ptr_eq(
            materialized.artifact(),
            materialized.callable().artifact()
        ));
        assert!(Arc::ptr_eq(
            materialized.artifact(),
            materialized.factory().artifact()
        ));
        assert_eq!(
            materialized
                .artifact()
                .query_source()
                .map(|source| source.as_ref()),
            Some(source)
        );
        assert_eq!(
            materialized.callable().semantics().lexical_parent(),
            Some(materialized.factory().id())
        );
        assert_eq!(
            materialized.callable().semantics().kind(),
            brokk_bifrost_analysis::analyzer::semantic::ProcedureKind::Lambda
        );
        let captures = materialized
            .bind_per_creation_captures()
            .expect("capture proof is complete");
        assert!(!captures.is_empty(), "fixture must contain a real capture");
        assert_eq!(captures.len(), materialized.captures().slots().len());
        assert!(
            captures
                .iter()
                .all(|binding| binding.target == materialized.callable().id())
        );
    }
}
