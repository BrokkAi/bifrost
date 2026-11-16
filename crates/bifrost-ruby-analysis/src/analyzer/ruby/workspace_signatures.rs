//! Ruby method signatures declared in workspace RBS files (#12967).
//!
//! A workspace RBS file (`sig/**/*.rbs`) declares the types of a Ruby
//! method's parameters, for example
//! `def total: (Hash[String, untyped] order) -> Integer`. The bounded Ruby
//! receiver typer trusts such a declaration as a contract, the way it trusts
//! an inline Sorbet `sig` (#12887). This module reads one file's bytes into
//! the facts the typer needs: per method, its owner, name and side, its
//! overload count, and the class type of each leading required positional.
//! Whether a named class is external or shadowed by a workspace declaration
//! depends on the workspace and the activated models, so that check happens
//! when the typer reads the facts, never here.

use std::path::Path;

use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_child_of_kind as direct_child, named_children_of_kind,
    named_children_vec as named_children,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use tree_sitter::{Node, Parser};

use brokk_bifrost_analysis::analyzer::workspace_authority::{
    AuthorityInputs, record_workspace_authority_read,
};
use brokk_bifrost_analysis::analyzer::{FactSubject, Language, WorkspaceFactFamily};

use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, StoreError};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::WorkspaceSignatureProducer;
use brokk_bifrost_core::hash::HashSet;
use git2::Oid;
use std::sync::Mutex;

use super::rbs_artifact::{declaration_body, is_trivia, unwrap_type};
use super::{RubyAnalyzer, signature_storage};

/// More methods than this in one file is not a hand-written signature file;
/// the file then contributes nothing rather than a truncated set, which could
/// hide a second declaration of a method.
const MAX_SIGNATURE_METHODS: usize = 50_000;
/// Deeper namespace nesting than this is refused the same way.
const MAX_NAMESPACE_DEPTH: usize = 64;

/// A constant path an RBS type names, as written: `::Hash` is absolute,
/// `Hash` and `A::Hash` are relative to the declaring namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RbsTypeName {
    pub(crate) absolute: bool,
    pub(crate) segments: Box<[Box<str>]>,
}

/// A non-optional class type, `Name` or `Name[Args]`. `element` is the class
/// of a sole type argument that is itself a class type, which the typer uses
/// only for `Array[E]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RbsClassType {
    pub(crate) name: RbsTypeName,
    pub(crate) argument_count: u32,
    pub(crate) element: Option<RbsTypeName>,
}

/// One `def` member of a class or module declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RubySignatureMethod {
    /// The owner's constant path segments, outermost first.
    pub(crate) owner: Box<[Box<str>]>,
    pub(crate) member: Box<str>,
    pub(crate) is_singleton: bool,
    pub(crate) overload_count: u32,
    /// The required positionals before any optional, rest or trailing one.
    /// Zero unless there is exactly one overload.
    pub(crate) leading_required: u32,
    /// One entry per leading required positional; `None` where the declared
    /// type is not a plain class type. Empty unless there is exactly one
    /// overload.
    pub(crate) positionals: Box<[Option<RbsClassType>]>,
}

impl RubySignatureMethod {
    pub(crate) fn owner_name(&self) -> String {
        self.owner.join("::")
    }

    fn retained_bytes(&self) -> usize {
        let segments = |segments: &[Box<str>]| {
            std::mem::size_of_val(segments)
                + segments.iter().map(|segment| segment.len()).sum::<usize>()
        };
        segments(&self.owner)
            + self.member.len()
            + std::mem::size_of_val(&*self.positionals)
            + self
                .positionals
                .iter()
                .flatten()
                .map(|class| {
                    segments(&class.name.segments)
                        + class
                            .element
                            .as_ref()
                            .map_or(0, |element| segments(&element.segments))
                })
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RubySignatureParseState {
    Complete,
    ParseError,
    OverLimit,
}

impl RubySignatureParseState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ParseError => "parse_error",
            Self::OverLimit => "over_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubySignatureFile {
    pub(crate) state: RubySignatureParseState,
    pub(crate) methods: Vec<RubySignatureMethod>,
    /// Every class or module constant the file declares, `::`-joined. A
    /// relative type name that one of these could name is not typed.
    pub(crate) types: Vec<Box<str>>,
}

impl RubySignatureFile {
    fn refused(state: RubySignatureParseState) -> Self {
        Self {
            state,
            methods: Vec::new(),
            types: Vec::new(),
        }
    }
}

/// Whether `path` (workspace-relative) is a workspace signature input: an
/// `.rbs` file below a directory named exactly `sig`, the location `rbs` and
/// Steep read by default, nested per gem in a monorepo. Third-party
/// collections elsewhere describe gems, which dependency packs cover.
pub(crate) fn is_ruby_signature_input_path(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rbs")
        && path
            .parent()
            .is_some_and(|parent| parent.components().any(|part| part.as_os_str() == "sig"))
}

/// The outermost `sig` directory of a signature input path, which holds it
/// and its siblings.
pub(crate) fn ruby_signature_root(path: &Path) -> Option<std::path::PathBuf> {
    let mut root = std::path::PathBuf::new();
    for part in path.parent()?.components() {
        root.push(part);
        if part.as_os_str() == "sig" {
            return Some(root);
        }
    }
    None
}

/// Parse one RBS file into its method signatures. A file that does not parse
/// cleanly, is not UTF-8, exceeds the limits or is cancelled contributes no
/// methods.
pub(crate) fn produce_ruby_signature_file(
    source: &[u8],
    cancellation: Option<&CancellationToken>,
) -> RubySignatureFile {
    let Ok(source) = std::str::from_utf8(source) else {
        return RubySignatureFile::refused(RubySignatureParseState::ParseError);
    };
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rbs::LANGUAGE.into())
        .expect("tree-sitter RBS language must load");
    let Some(tree) = parser.parse(source, None) else {
        return RubySignatureFile::refused(RubySignatureParseState::ParseError);
    };
    let root = tree.root_node();
    if root.has_error() {
        return RubySignatureFile::refused(RubySignatureParseState::ParseError);
    }
    let mut methods = Vec::new();
    let mut types = Vec::new();
    // (declaration or member, owner segments, owner type parameters, and
    // whether every method below only marks its name as declared)
    // A `use` directive rebinds type names for the whole file, so nothing the
    // file declares is typed; its declarations still count.
    let file_uses = named_children(root)
        .into_iter()
        .any(|node| declaration_body(node).is_ok_and(|node| node.kind() == "use_directive"));
    let mut pending = named_children(root)
        .into_iter()
        .rev()
        .map(|node| {
            (
                node,
                Vec::<Box<str>>::new(),
                Vec::<Box<str>>::new(),
                file_uses,
            )
        })
        .collect::<Vec<_>>();
    while let Some((node, owner, type_parameters, refuse)) = pending.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return RubySignatureFile::refused(RubySignatureParseState::OverLimit);
        }
        if is_trivia(node.kind()) {
            continue;
        }
        let Ok(node) = declaration_body(node) else {
            continue;
        };
        let mut declared = Vec::new();
        match node.kind() {
            "class_decl" | "module_decl" => {
                let Some(name) = node.child_by_field_name("name") else {
                    continue;
                };
                let path = rbs_name_path(name, source);
                // `class A::B` nested in `module M` names M::A::B or ::A::B
                // depending on which exists. Its methods are recorded under
                // both owners as declared-but-untyped, so they can still make
                // another declaration ambiguous but type nothing themselves.
                let owners = if path.absolute || owner.is_empty() {
                    vec![(path.segments.into_vec(), refuse)]
                } else if path.segments.len() == 1 {
                    vec![(owner.iter().cloned().chain(path.segments).collect(), refuse)]
                } else {
                    vec![
                        (
                            owner
                                .iter()
                                .cloned()
                                .chain(path.segments.iter().cloned())
                                .collect(),
                            true,
                        ),
                        (path.segments.into_vec(), true),
                    ]
                };
                let parameters = node
                    .child_by_field_name("type_parameters")
                    .map(|parameters| type_variables(parameters, source))
                    .unwrap_or_default();
                for (segments, refuse) in owners {
                    if segments.len() > MAX_NAMESPACE_DEPTH || types.len() >= MAX_SIGNATURE_METHODS
                    {
                        return RubySignatureFile::refused(RubySignatureParseState::OverLimit);
                    }
                    types.push(segments.join("::").into());
                    if let Some(body) = node.child_by_field_name("body") {
                        for child in named_children(body).into_iter().rev() {
                            pending.push((child, segments.clone(), parameters.clone(), refuse));
                        }
                    }
                }
            }
            "class_alias_decl" | "module_alias_decl" => {
                let Some(name) = node.child_by_field_name("name") else {
                    continue;
                };
                let path = rbs_name_path(name, source);
                if types.len() >= MAX_SIGNATURE_METHODS {
                    return RubySignatureFile::refused(RubySignatureParseState::OverLimit);
                }
                if path.absolute || owner.is_empty() {
                    types.push(path.segments.join("::").into());
                } else {
                    // Either reading of a namespaced alias may be the one.
                    types.push(
                        owner
                            .iter()
                            .chain(path.segments.iter())
                            .map(AsRef::as_ref)
                            .collect::<Vec<&str>>()
                            .join("::")
                            .into(),
                    );
                    if path.segments.len() > 1 {
                        types.push(path.segments.join("::").into());
                    }
                }
            }
            "method_member" if !owner.is_empty() => {
                declared = signature_methods(node, &owner, &type_parameters, source);
            }
            // An alias or attribute also defines a method; the typer does not
            // read its signature, but it is a declaration all the same.
            "alias_member" if !owner.is_empty() => {
                declared = node
                    .child_by_field_name("name")
                    .map(|name| {
                        untyped_declarations(
                            &owner,
                            name_member(name, source),
                            direct_child(name, "self").is_some(),
                        )
                    })
                    .unwrap_or_default();
            }
            "attribute_member" if !owner.is_empty() => {
                let mut cursor = node.walk();
                let parts = node
                    .children_by_field_name("name", &mut cursor)
                    .collect::<Vec<_>>();
                let singleton = parts.iter().any(|part| part.kind() == "self");
                let kind = direct_child(node, "attribyte_type").map(|kind| node_text(kind, source));
                if let Some(name) = parts
                    .iter()
                    .find(|part| part.kind() == "method_name")
                    .map(|name| node_text(*name, source))
                {
                    if kind != Some("attr_writer") {
                        declared = untyped_declarations(&owner, Some(name), singleton);
                    }
                    if kind != Some("attr_reader") {
                        declared.extend(untyped_declarations(
                            &owner,
                            Some(&format!("{name}=")),
                            singleton,
                        ));
                    }
                }
            }
            _ => {}
        }
        for mut method in declared {
            if methods.len() >= MAX_SIGNATURE_METHODS {
                return RubySignatureFile::refused(RubySignatureParseState::OverLimit);
            }
            if refuse {
                method.overload_count = 0;
                method.leading_required = 0;
                method.positionals = Box::default();
            }
            methods.push(method);
        }
    }
    RubySignatureFile {
        state: RubySignatureParseState::Complete,
        methods,
        types,
    }
}

/// The `method_name` text of an alias name, which may be wrapped in a
/// `singleton_method_name`.
fn name_member<'a>(name: Node<'_>, source: &'a str) -> Option<&'a str> {
    if name.kind() == "method_name" {
        return Some(node_text(name, source));
    }
    direct_child(name, "method_name").map(|name| node_text(name, source))
}

/// A declaration of `member` whose signature the typer does not read: it
/// types nothing, but a second declaration of the same name is ambiguous.
fn untyped_declarations(
    owner: &[Box<str>],
    member: Option<&str>,
    is_singleton: bool,
) -> Vec<RubySignatureMethod> {
    member
        .filter(|member| !member.is_empty())
        .map(|member| RubySignatureMethod {
            owner: owner.into(),
            member: member.into(),
            is_singleton,
            overload_count: 0,
            leading_required: 0,
            positionals: Box::default(),
        })
        .into_iter()
        .collect()
}

/// The declarations one `def` member makes: one side, or both for
/// `def self?.name` (module_function), which the typer does not match.
fn signature_methods(
    method: Node<'_>,
    owner: &[Box<str>],
    owner_type_parameters: &[Box<str>],
    source: &str,
) -> Vec<RubySignatureMethod> {
    let mut cursor = method.walk();
    let parts = method
        .children_by_field_name("name", &mut cursor)
        .collect::<Vec<_>>();
    if parts.iter().any(|part| part.kind() == "?.") {
        let member = parts
            .iter()
            .find(|part| part.kind() == "method_name")
            .map(|name| node_text(*name, source));
        let mut both = untyped_declarations(owner, member, false);
        both.extend(untyped_declarations(owner, member, true));
        return both;
    }
    signature_method(method, owner, owner_type_parameters, source)
        .into_iter()
        .collect()
}

fn signature_method(
    method: Node<'_>,
    owner: &[Box<str>],
    owner_type_parameters: &[Box<str>],
    source: &str,
) -> Option<RubySignatureMethod> {
    let mut cursor = method.walk();
    let mut is_singleton = false;
    let mut member = None;
    for part in method.children_by_field_name("name", &mut cursor) {
        match part.kind() {
            "self" => is_singleton = true,
            "method_name" => member = Some(node_text(part, source)),
            _ => {}
        }
    }
    let member = member.filter(|member| !member.is_empty())?;
    let overloads = direct_child(method, "method_types")
        .map(|types| named_children_of_kind(types, "method_type"))
        .unwrap_or_default();
    let mut signature = RubySignatureMethod {
        owner: owner.into(),
        member: member.into(),
        is_singleton,
        overload_count: u32::try_from(overloads.len()).unwrap_or(u32::MAX),
        leading_required: 0,
        positionals: Box::default(),
    };
    let [overload] = overloads.as_slice() else {
        return Some(signature);
    };
    let mut type_parameters = owner_type_parameters.to_vec();
    if let Some(parameters) = overload.child_by_field_name("type_parameters") {
        type_parameters.extend(type_variables(parameters, source));
    }
    let leading = overload
        .child_by_field_name("body")
        .and_then(|body| direct_child(body, "parameters"))
        .and_then(|parameters| {
            named_children(parameters)
                .into_iter()
                .find(|group| !is_trivia(group.kind()))
        })
        .filter(|group| group.kind() == "required_positionals")
        .map(|group| named_children_of_kind(group, "parameter"))
        .unwrap_or_default();
    signature.leading_required = u32::try_from(leading.len()).unwrap_or(u32::MAX);
    signature.positionals = leading
        .into_iter()
        .map(|parameter| {
            direct_child(parameter, "type")
                .and_then(|declared| class_type(declared, &type_parameters, source))
        })
        .collect();
    Some(signature)
}

/// The class type `declared` names, when it is a plain class type. A name
/// that is a type variable in scope is not a class.
fn class_type(
    declared: Node<'_>,
    type_parameters: &[Box<str>],
    source: &str,
) -> Option<RbsClassType> {
    let declared = unwrap_type(declared);
    let name = class_type_name(declared, type_parameters, source)?;
    let arguments = direct_child(declared, "type_arguments")
        .map(|arguments| named_children_of_kind(arguments, "type"))
        .unwrap_or_default();
    let element = match arguments.as_slice() {
        [argument] => class_type_name(unwrap_type(*argument), type_parameters, source),
        _ => None,
    };
    Some(RbsClassType {
        name,
        argument_count: u32::try_from(arguments.len()).unwrap_or(u32::MAX),
        element,
    })
}

fn class_type_name(
    declared: Node<'_>,
    type_parameters: &[Box<str>],
    source: &str,
) -> Option<RbsTypeName> {
    if declared.kind() != "class_type" {
        return None;
    }
    let name = rbs_name_path(direct_child(declared, "class_name")?, source);
    let is_type_variable =
        !name.absolute && matches!(&*name.segments, [only] if type_parameters.contains(only));
    (!name.segments.is_empty() && !is_type_variable).then_some(name)
}

/// The constants of a `class_name` or `module_name`, outermost first, and
/// whether a leading `::` makes it absolute. The grammar nests the qualifier
/// as `namespace` nodes whose first token is `::` only for an absolute path.
fn rbs_name_path(name: Node<'_>, source: &str) -> RbsTypeName {
    let mut segments = Vec::new();
    let mut absolute = None;
    let mut pending = vec![name];
    while let Some(node) = pending.pop() {
        if node.child_count() == 0 {
            absolute.get_or_insert(node.kind() == "::");
        }
        if node.kind() == "constant" {
            absolute.get_or_insert(false);
            segments.push(node_text(node, source).into());
            continue;
        }
        let mut cursor = node.walk();
        let children = node.children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    RbsTypeName {
        absolute: absolute.unwrap_or(false),
        segments: segments.into(),
    }
}

fn type_variables(parameters: Node<'_>, source: &str) -> Vec<Box<str>> {
    let mut variables = Vec::new();
    let mut pending = vec![parameters];
    while let Some(node) = pending.pop() {
        if node.kind() == "type_variable" {
            variables.push(node_text(node, source).into());
            continue;
        }
        pending.extend(named_children(node));
    }
    variables
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::try_node_source_text(node, source)
        .expect("tree-sitter RBS ranges fall on UTF-8 boundaries of a str source")
}

/// What the workspace declares for one method name on one side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RubySignatureDeclaration {
    None,
    /// Declared more than once across the workspace's signature files.
    Ambiguous,
    One(RubySignatureMethod),
}

impl RubySignatureDeclaration {
    fn add(&mut self, method: RubySignatureMethod) {
        *self = match std::mem::replace(self, Self::None) {
            Self::None => Self::One(method),
            Self::One(_) | Self::Ambiguous => Self::Ambiguous,
        };
    }

    fn hash(&self, hasher: &mut CanonicalHasher, side: &str) {
        match self {
            Self::None => hasher.field(side, b"none"),
            Self::Ambiguous => hasher.field(side, b"ambiguous"),
            Self::One(method) => {
                hasher.field(side, b"one");
                hasher.field("overloads", &method.overload_count.to_be_bytes());
                hasher.field("leading", &method.leading_required.to_be_bytes());
                for positional in &method.positionals {
                    match positional {
                        None => hasher.field("positional", b"untyped"),
                        Some(class) => {
                            hasher.field("positional", b"class");
                            hash_name(hasher, "name", &class.name);
                            hasher.field("arguments", &class.argument_count.to_be_bytes());
                            match &class.element {
                                None => hasher.field("element", b"none"),
                                Some(element) => hash_name(hasher, "element", element),
                            }
                        }
                    }
                }
            }
        }
    }
}

fn hash_name(hasher: &mut CanonicalHasher, field: &str, name: &RbsTypeName) {
    hasher.field(field, &[u8::from(name.absolute)]);
    for segment in &name.segments {
        hasher.value(segment.as_bytes());
    }
}

/// The workspace's signature declarations of one `(owner, member)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubyWorkspaceSignatureAnswer {
    pub(crate) instance: RubySignatureDeclaration,
    pub(crate) singleton: RubySignatureDeclaration,
}

impl RubyWorkspaceSignatureAnswer {
    /// What a signature file whose facts are unknown allows: any declaration
    /// may be repeated there.
    pub(crate) fn unknown() -> Self {
        Self {
            instance: RubySignatureDeclaration::Ambiguous,
            singleton: RubySignatureDeclaration::Ambiguous,
        }
    }

    /// `methods` must already be the declarations of one `(owner, member)`.
    pub(crate) fn new(methods: impl IntoIterator<Item = RubySignatureMethod>) -> Self {
        let mut answer = Self {
            instance: RubySignatureDeclaration::None,
            singleton: RubySignatureDeclaration::None,
        };
        for method in methods {
            if method.is_singleton {
                answer.singleton.add(method);
            } else {
                answer.instance.add(method);
            }
        }
        answer
    }

    /// The caller-visible answer only: never paths or blob identities, so an
    /// edit that leaves this method's declarations alone keeps the digest.
    pub(crate) fn digest(&self) -> StableDigest {
        let mut hasher = CanonicalHasher::new(b"bifrost-ruby-workspace-signature-answer:v1");
        self.instance.hash(&mut hasher, "instance");
        self.singleton.hash(&mut hasher, "singleton");
        StableDigest::from_array(hasher.finish())
    }

    /// For every relative type name a declaration uses, each constant it
    /// could name in the declaring owner's namespaces, innermost last.
    fn nested_type_candidates(&self) -> Vec<String> {
        let mut candidates = Vec::new();
        for method in [&self.instance, &self.singleton]
            .into_iter()
            .filter_map(|declaration| match declaration {
                RubySignatureDeclaration::One(method) => Some(method),
                RubySignatureDeclaration::None | RubySignatureDeclaration::Ambiguous => None,
            })
        {
            for name in method
                .positionals
                .iter()
                .flatten()
                .flat_map(|class| std::iter::once(&class.name).chain(class.element.as_ref()))
            {
                if name.absolute {
                    continue;
                }
                for end in 1..=method.owner.len() {
                    candidates.push(format!(
                        "{}::{}",
                        method.owner[..end].join("::"),
                        name.segments.join("::")
                    ));
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }

    /// Drop every type whose relative name a declared constant in the
    /// owner's namespaces could name.
    fn untype_declared_nested(&mut self, declared: impl Fn(&str) -> bool) {
        let shadowed = |owner: &[Box<str>], name: &RbsTypeName| {
            !name.absolute
                && (1..=owner.len()).any(|end| {
                    declared(&format!(
                        "{}::{}",
                        owner[..end].join("::"),
                        name.segments.join("::")
                    ))
                })
        };
        for declaration in [&mut self.instance, &mut self.singleton] {
            let RubySignatureDeclaration::One(method) = declaration else {
                continue;
            };
            let owner = method.owner.clone();
            for positional in method.positionals.iter_mut() {
                if positional
                    .as_ref()
                    .is_some_and(|class| shadowed(&owner, &class.name))
                {
                    *positional = None;
                }
                if let Some(class) = positional
                    && class
                        .element
                        .as_ref()
                        .is_some_and(|element| shadowed(&owner, element))
                {
                    class.element = None;
                }
            }
        }
    }

    /// Heap bytes this answer retains, for the memo's byte budget.
    pub(crate) fn retained_bytes(&self) -> usize {
        let declaration = |declaration: &RubySignatureDeclaration| match declaration {
            RubySignatureDeclaration::One(method) => method.retained_bytes(),
            RubySignatureDeclaration::None | RubySignatureDeclaration::Ambiguous => 0,
        };
        std::mem::size_of::<Self>() + declaration(&self.instance) + declaration(&self.singleton)
    }

    pub(crate) fn declaration(&self, singleton: bool) -> &RubySignatureDeclaration {
        if singleton {
            &self.singleton
        } else {
            &self.instance
        }
    }
}

pub(super) fn signature_inputs(
    owner: &str,
    member: &str,
    answer: &RubyWorkspaceSignatureAnswer,
) -> AuthorityInputs<'static> {
    AuthorityInputs::Fact {
        language: Language::Ruby,
        subject: FactSubject::NamedMember {
            owner: owner.into(),
            member: member.into(),
        },
        answer: answer.digest(),
    }
}

/// The workspace's declarations of `member` of `owner`. `None` means
/// `keep_going` stopped the read. Disk signature files are read from their
/// stored facts; a file an unsaved overlay shadows is parsed from the
/// overlay bytes for this snapshot and never stored. A file whose facts are
/// unknown (unreadable, unpublished, or collected) makes every declaration
/// ambiguous, since it may declare the method again.
pub(super) fn workspace_signature_answer(
    ruby: &RubyAnalyzer,
    owner: &str,
    member: &str,
    heads_known: &Mutex<Option<Option<i64>>>,
    keep_going: &dyn Fn() -> bool,
) -> Option<RubyWorkspaceSignatureAnswer> {
    let answer = read_workspace_signature(ruby, owner, member, heads_known, keep_going)?;
    record_workspace_authority_read(
        ruby,
        WorkspaceFactFamily::RubyWorkspaceSignatures,
        signature_inputs(owner, member, &answer),
    );
    Some(answer)
}

fn read_workspace_signature(
    ruby: &RubyAnalyzer,
    owner: &str,
    member: &str,
    heads_known: &Mutex<Option<Option<i64>>>,
    keep_going: &dyn Fn() -> bool,
) -> Option<RubyWorkspaceSignatureAnswer> {
    let project = &ruby.inner.project;
    let store = ruby.inner.analyzer_store();
    let overlays = project.overlay_content();
    let overlaid = overlays
        .as_deref()
        .map(|overlays| {
            overlays
                .entries()
                .iter()
                .map(|(file, _)| file)
                .filter(|file| is_ruby_signature_input_path(file.rel_path()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let overlaid_paths = overlaid
        .iter()
        .map(|file| brokk_bifrost_core::path_utils::rel_path_string(file))
        .collect::<HashSet<_>>();
    let blobs = ruby
        .inner
        .signature_inputs()
        .iter()
        .filter(|(path, _)| !overlaid_paths.contains(path.as_ref()))
        .map(|(_, oid)| *oid)
        .collect::<Vec<_>>();
    let mut overlay_methods = Vec::new();
    let mut overlay_types = HashSet::<Box<str>>::default();
    for file in overlaid {
        if !keep_going() {
            return None;
        }
        let Ok(snapshot) = project.read_file_snapshot(file) else {
            return Some(RubyWorkspaceSignatureAnswer::unknown());
        };
        let parsed = produce_ruby_signature_file(snapshot.bytes(), None);
        if parsed.state != RubySignatureParseState::Complete {
            return Some(RubyWorkspaceSignatureAnswer::unknown());
        }
        overlay_methods.extend(
            parsed
                .methods
                .into_iter()
                .filter(|method| *method.member == *member && method.owner_name() == owner),
        );
        overlay_types.extend(parsed.types);
    }
    // A head can go missing after the build published it, when garbage
    // collection runs under an older snapshot. The heads are checked once
    // per snapshot and again only after a collection deleted some head;
    // every read confirms the collection epoch it was checked at.
    let mut recheck = false;
    loop {
        let checked = {
            let mut cached = heads_known.lock().expect("signature heads lock poisoned");
            if recheck || cached.is_none() {
                *cached = Some(if blobs.iter().any(|oid| oid.is_zero()) {
                    None
                } else {
                    signature_storage::ruby_signature_heads_present(store, &blobs).unwrap_or_else(
                        |error| {
                            eprintln!("could not read Ruby signature heads: {error}");
                            None
                        },
                    )
                });
            }
            cached.expect("signature heads were just checked")
        };
        let Some(epoch) = checked else {
            return Some(RubyWorkspaceSignatureAnswer::unknown());
        };
        match read_stored_signature(
            store,
            owner,
            member,
            &blobs,
            epoch,
            &overlay_methods,
            &overlay_types,
        ) {
            Ok(Some(answer)) => return Some(answer),
            Ok(None) if !recheck => recheck = true,
            Ok(None) => return Some(RubyWorkspaceSignatureAnswer::unknown()),
            Err(error) => {
                eprintln!("could not read Ruby signature facts for {owner}#{member}: {error}");
                return Some(RubyWorkspaceSignatureAnswer::unknown());
            }
        }
    }
}

/// The answer from the stored facts of `blobs` and the overlay facts, or
/// `None` when a collection deleted a head since `epoch`. A relative type
/// name that a declared constant in one of the owner's namespaces could name
/// (RBS resolves those first) types nothing.
fn read_stored_signature(
    store: &AnalyzerStore,
    owner: &str,
    member: &str,
    blobs: &[Oid],
    epoch: i64,
    overlay_methods: &[RubySignatureMethod],
    overlay_types: &HashSet<Box<str>>,
) -> Result<Option<RubyWorkspaceSignatureAnswer>, StoreError> {
    let Some(stored) =
        signature_storage::ruby_signature_methods_named(store, owner, member, blobs, epoch)?
    else {
        return Ok(None);
    };
    let mut answer = RubyWorkspaceSignatureAnswer::new(
        stored
            .into_iter()
            .flatten()
            .chain(overlay_methods.iter().cloned()),
    );
    let candidates = answer.nested_type_candidates();
    if candidates.is_empty() {
        return Ok(Some(answer));
    }
    let Some(stored_types) =
        signature_storage::ruby_signature_types_declared(store, &candidates, blobs, epoch)?
    else {
        return Ok(None);
    };
    answer.untype_declared_nested(|name| {
        overlay_types.contains(name) || stored_types.iter().any(|declared| declared == name)
    });
    Ok(Some(answer))
}

/// The adapter's [`WorkspaceSignatureProducer`] for Ruby.
pub(crate) struct RubyWorkspaceSignatures;

impl WorkspaceSignatureProducer for RubyWorkspaceSignatures {
    fn is_signature_input_path(&self, path: &Path) -> bool {
        is_ruby_signature_input_path(path)
    }

    fn publish(&self, store: &AnalyzerStore, oid: Oid, source: &[u8]) -> Result<bool, StoreError> {
        let file = produce_ruby_signature_file(source, None);
        let complete = file.state == RubySignatureParseState::Complete;
        signature_storage::publish_ruby_signature_file(store, oid, file)?;
        Ok(complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins which tree-sitter-rbs 0.2.2 node kinds carry the shapes the
    /// producer reads: a class-typed required positional, an optional
    /// positional, an optional type, a singleton `def`, an absolute name,
    /// and the alias and attribute members that declare a name untyped.
    #[test]
    fn rbs_grammar_carries_the_signature_shapes() {
        let source = "module Shop\n  class Calc[T]\n    def total: (Hash[String, untyped] order, ::Array[Hash[String, Integer]] lines, Hash[String, untyped]? maybe, T item, ?Integer x) -> Integer\n    def self.build: () -> Calc | (Integer) -> Calc\n    def self?.both: (String s) -> void\n    alias sum total\n    attr_reader label: String\n  end\nend\n";
        let file = produce_ruby_signature_file(source.as_bytes(), None);
        assert_eq!(file.state, RubySignatureParseState::Complete);
        let name = |absolute, segments: &[&str]| RbsTypeName {
            absolute,
            segments: segments.iter().map(|segment| Box::from(*segment)).collect(),
        };
        assert_eq!(
            file.methods,
            vec![
                RubySignatureMethod {
                    owner: vec!["Shop".into(), "Calc".into()].into(),
                    member: "total".into(),
                    is_singleton: false,
                    overload_count: 1,
                    leading_required: 4,
                    positionals: vec![
                        Some(RbsClassType {
                            name: name(false, &["Hash"]),
                            argument_count: 2,
                            element: None,
                        }),
                        Some(RbsClassType {
                            name: name(true, &["Array"]),
                            argument_count: 1,
                            element: Some(name(false, &["Hash"])),
                        }),
                        None,
                        None,
                    ]
                    .into(),
                },
                RubySignatureMethod {
                    owner: vec!["Shop".into(), "Calc".into()].into(),
                    member: "build".into(),
                    is_singleton: true,
                    overload_count: 2,
                    leading_required: 0,
                    positionals: Box::default(),
                },
                RubySignatureMethod {
                    owner: vec!["Shop".into(), "Calc".into()].into(),
                    member: "both".into(),
                    is_singleton: false,
                    overload_count: 0,
                    leading_required: 0,
                    positionals: Box::default(),
                },
                RubySignatureMethod {
                    owner: vec!["Shop".into(), "Calc".into()].into(),
                    member: "both".into(),
                    is_singleton: true,
                    overload_count: 0,
                    leading_required: 0,
                    positionals: Box::default(),
                },
                RubySignatureMethod {
                    owner: vec!["Shop".into(), "Calc".into()].into(),
                    member: "sum".into(),
                    is_singleton: false,
                    overload_count: 0,
                    leading_required: 0,
                    positionals: Box::default(),
                },
                RubySignatureMethod {
                    owner: vec!["Shop".into(), "Calc".into()].into(),
                    member: "label".into(),
                    is_singleton: false,
                    overload_count: 0,
                    leading_required: 0,
                    positionals: Box::default(),
                },
            ]
        );
        assert_eq!(file.types, vec![Box::from("Shop"), Box::from("Shop::Calc")]);
        // A `use` directive rebinds names for the whole file: its methods are
        // declared but untyped.
        let using = produce_ruby_signature_file(
            b"use Other::Hash\nclass A\n  def m: (Hash[String, untyped] x) -> void\nend\n",
            None,
        );
        assert_eq!(
            using
                .methods
                .iter()
                .map(|method| (&*method.member, method.overload_count))
                .collect::<Vec<_>>(),
            vec![("m", 0)]
        );
        assert!(is_ruby_signature_input_path(Path::new("gems/a/sig/a.rbs")));
        assert!(!is_ruby_signature_input_path(Path::new("types/a.rbs")));
        assert!(!is_ruby_signature_input_path(Path::new("sig.rbs")));
    }
}
