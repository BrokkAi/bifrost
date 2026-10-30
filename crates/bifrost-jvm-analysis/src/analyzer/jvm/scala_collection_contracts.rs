//! Collection-flow contracts for the Scala standard library's mutable `Map`.
//!
//! Only an exact scala-library source artifact publishes these contracts, and
//! only for the declarations that artifact itself proves. The contracts follow
//! Scala dispatch rather than the static receiver type:
//!
//! - `scala.collection.mutable.Map` declares none of `apply`, `update` or
//!   `foreach`; it inherits them from `collection.MapOps`, `mutable.MapOps`
//!   and `IterableOnceOps`. Those inherited members are published on `Map`
//!   itself, with their signatures substituted through the inheritance chain,
//!   because a receiver-arguments substitution must name the callable's own
//!   receiver type. Their contracts are partial: any `Map` implementation may
//!   override them, so they describe the declared protocol, not a dispatch
//!   target.
//! - `mutable.Map[K, V](..)` is `MapFactory.Delegate[Map](HashMap)`, so its
//!   runtime class is exactly `mutable.HashMap`, which overrides all three
//!   members. The factory `apply` is published on `Map` with
//!   `exact_return_classes = [HashMap[K, V]]`, and `HashMap`'s own overrides
//!   carry the complete contracts. A consumer that proves a receiver came from
//!   that factory binds the `HashMap` contracts; every other receiver,
//!   including a user subclass, stays unmodeled.
//!
//! The declarations, parents and member signatures are read from the
//! artifact's own syntax. What the artifact cannot show structurally is that
//! `HashMap`'s companion `from` builds a `new HashMap` and that the three
//! overrides store, read and visit entries; those are the standard-library
//! semantics this producer asserts for the exact artifact selector.

use brokk_bifrost_analysis::analyzer::semantic_model::{
    CollectionFlowFact, Completeness, MemberFact, MemberKind, Parameter, ReceiverFact, Signature,
    TypeFact, TypeKind, TypeRef,
};
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::scala_facts::ScalaTypeExpressionPath;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::scala::supertypes::{ScalaSupertypeLookupPath, scala_type_lookup_segments};
use brokk_bifrost_semantic::analyzer::semantic_model::csmi::{
    CsmiCollectionFlowBoundaryRoot, CsmiCollectionFlowEntryComponent, CsmiCollectionFlowInvocation,
    CsmiCollectionFlowKind, CsmiCollectionFlowPayload, CsmiCollectionFlowRoot,
    CsmiCollectionFlowShape, CsmiCollectionFlowSubstitution, CsmiCollectionFlowTiming,
    CsmiCollectionFlowTransfer, CsmiInputBoundaryRoot, CsmiInputLocation, CsmiInputParameterRoot,
    CsmiInputPhase, CsmiInputReceiverRoot, CsmiIntrinsicType, CsmiIntrinsicTypeKind,
    CsmiOutputBoundaryRoot, CsmiOutputLocation, CsmiOutputPhase, CsmiOutputReceiverRoot,
    CsmiOutputResultRoot, CsmiParameterRootRole, CsmiProjection, CsmiProjectionStep,
    CsmiReceiverRootRole, CsmiResultRootRole, CsmiTypeExpression,
};
use brokk_bifrost_semantic::analyzer::semantic_model::identity::{
    MemberIdentity, member_declaration_id,
};
use brokk_bifrost_semantic::analyzer::semantic_model::producer::BoundedProducerDiagnostics;
use tree_sitter::Node;

pub(super) const SCALA_MUTABLE_MAP: &str = "scala.collection.mutable.Map";
pub(super) const SCALA_MUTABLE_HASH_MAP: &str = "scala.collection.mutable.HashMap";
const SCALA_MAP_FACTORY: &str = "scala.collection.MapFactory";
const SCALA_MAP_FACTORY_DELEGATE: &str = "scala.collection.MapFactory.Delegate";
/// Bound on the base classes one linearization may hold. The standard `Map`
/// has a few dozen; a larger closure is not the library this module models.
const MAX_LINEARIZATION_BASES: usize = 256;
/// Bound on the nesting of one substituted type reference.
const MAX_TYPE_DEPTH: usize = 32;

/// The members whose contracts this module publishes, with their arity.
const MAP_PROTOCOL: [(&str, usize); 3] = [("apply", 1), ("update", 2), ("foreach", 1)];

/// Whether a member of `owner` publishes a receiver root. Only the modeled
/// collection owners do, because only their contracts read one.
pub(super) fn publishes_collection_receiver(owner: &str) -> bool {
    owner == SCALA_MUTABLE_MAP || owner == SCALA_MUTABLE_HASH_MAP
}

/// Where one top-level artifact type resolves the names its declaration
/// spells: the parser's package scopes, the definitions of its compilation
/// unit, and the unit-level imports that precede it.
#[derive(Debug, Clone)]
pub(super) struct ScalaArtifactTypeScope {
    name: String,
    module: bool,
    /// Parser-established package scopes, outermost to innermost.
    package_prefixes: Vec<String>,
    /// Top-level types of the same compilation unit, by simple name.
    same_unit: HashMap<String, String>,
    explicit_imports: Vec<(String, Vec<String>)>,
    wildcard_imports: Vec<Vec<String>>,
    supertypes: Vec<ScalaTypeExpressionPath>,
    /// The single parent an `object` applies, as in
    /// `object Map extends MapFactory.Delegate[Map](HashMap)`.
    parent_application: Option<ScalaParentApplication>,
}

#[derive(Debug, Clone)]
struct ScalaParentApplication {
    parent: Vec<String>,
    type_arguments: Vec<Vec<String>>,
    value_arguments: Vec<Vec<String>>,
}

/// The scope of one top-level type declaration. A nested declaration also
/// sees its enclosing templates' members, which this resolver does not model,
/// so it has no scope and every name it spells stays unresolved.
#[allow(clippy::too_many_arguments)]
pub(super) fn scala_artifact_type_scope(
    name: String,
    declaration: &CodeUnit,
    node: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    module: bool,
    supertypes: Vec<ScalaTypeExpressionPath>,
    same_unit: &HashMap<String, String>,
) -> ScalaArtifactTypeScope {
    let package_prefixes = parsed
        .supertype_lookup_paths
        .get(declaration)
        .and_then(|paths| paths.first())
        .and_then(|path| ScalaSupertypeLookupPath::decode(path))
        .map(|path| path.package_prefixes().to_vec())
        .filter(|prefixes| !prefixes.is_empty())
        .unwrap_or_else(|| vec![parsed.package_name.clone()]);
    let mut explicit_imports = Vec::new();
    let mut wildcard_imports = Vec::new();
    for import in &parsed.imports {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        if !path.lexical_scopes.is_empty() || path.declaration_start_byte >= node.start_byte() {
            continue;
        }
        if import.is_wildcard {
            wildcard_imports.push(path.segments.clone());
        } else if let Some(bound) = import.identifier.clone() {
            explicit_imports.push((bound, path.segments.clone()));
        }
    }
    ScalaArtifactTypeScope {
        name,
        module,
        package_prefixes,
        same_unit: same_unit.clone(),
        explicit_imports,
        wildcard_imports,
        supertypes,
        parent_application: module.then(|| parent_application(node, source)).flatten(),
    }
}

/// The one parent an `object` extends, with its type and value arguments,
/// when every part is a plain stable path.
fn parent_application(node: Node<'_>, source: &str) -> Option<ScalaParentApplication> {
    let clause = node.child_by_field_name("extend")?;
    let mut cursor = clause.walk();
    let parents = clause
        .children_by_field_name("type", &mut cursor)
        .filter(|child| child.is_named())
        .collect::<Vec<_>>();
    let [parent] = parents.as_slice() else {
        return None;
    };
    let (parent_type, type_arguments) = match parent.kind() {
        "generic_type" => {
            let arguments = parent.child_by_field_name("type_arguments")?;
            let mut cursor = arguments.walk();
            let type_arguments = arguments
                .named_children(&mut cursor)
                .map(|argument| stable_path(argument, source))
                .collect::<Option<Vec<_>>>()?;
            (parent.child_by_field_name("type")?, type_arguments)
        }
        "type_identifier" | "stable_type_identifier" => (*parent, Vec::new()),
        _ => return None,
    };
    let mut cursor = clause.walk();
    let argument_lists = clause
        .children_by_field_name("arguments", &mut cursor)
        .collect::<Vec<_>>();
    let value_arguments = match argument_lists.as_slice() {
        [] => Vec::new(),
        [arguments] => {
            let mut cursor = arguments.walk();
            arguments
                .named_children(&mut cursor)
                .map(|argument| stable_path(argument, source))
                .collect::<Option<Vec<_>>>()?
        }
        _ => return None,
    };
    Some(ScalaParentApplication {
        parent: stable_path(parent_type, source)?,
        type_arguments,
        value_arguments,
    })
}

fn stable_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "stable_type_identifier" | "stable_identifier"
    )
    .then(|| scala_type_lookup_segments(node, source))
    .filter(|segments| !segments.is_empty())
}

/// The qualified names one artifact declares, which is everything the
/// resolver may bind a spelled name to.
struct ArtifactNames<'facts> {
    types: HashMap<&'facts str, &'facts TypeFact>,
    packages: HashSet<String>,
    modules: HashSet<&'facts str>,
}

impl<'facts> ArtifactNames<'facts> {
    fn new(types: &'facts [TypeFact], scopes: &'facts [ScalaArtifactTypeScope]) -> Self {
        let mut packages = HashSet::default();
        for scope in scopes {
            for prefix in &scope.package_prefixes {
                let mut package = prefix.as_str();
                while !package.is_empty() && packages.insert(package.to_owned()) {
                    let Some((parent, _)) = package.rsplit_once('.') else {
                        break;
                    };
                    package = parent;
                }
            }
        }
        Self {
            types: types
                .iter()
                .map(|fact| (fact.name.as_str(), fact))
                .collect(),
            packages,
            modules: scopes
                .iter()
                .filter(|scope| scope.module)
                .map(|scope| scope.name.as_str())
                .collect(),
        }
    }

    fn knows(&self, qualified: &str) -> bool {
        self.types.contains_key(qualified) || self.packages.contains(qualified)
    }

    /// The qualified type a written path names from `scope`, when Scala's
    /// binding precedence selects exactly one declaration of this artifact.
    fn resolve_type(&self, scope: &ScalaArtifactTypeScope, segments: &[String]) -> Option<String> {
        let (root, rest) = segments.split_first()?;
        let qualified = qualify(&self.resolve_root(scope, root)?, rest);
        self.types
            .contains_key(qualified.as_str())
            .then_some(qualified)
    }

    /// Bind the first segment of a written path. Definitions of the same
    /// compilation unit win, then explicit imports, then wildcard imports,
    /// then package members from the innermost package scope outward, then
    /// the root package and the implicit `scala._` import. A binding this
    /// artifact cannot enumerate -- an import of an unknown entity, or a
    /// wildcard over one -- leaves the name unresolved rather than letting a
    /// lower-precedence declaration answer for it.
    fn resolve_root(&self, scope: &ScalaArtifactTypeScope, root: &str) -> Option<String> {
        if let Some(qualified) = scope.same_unit.get(root) {
            return Some(qualified.clone());
        }
        let explicit = scope
            .explicit_imports
            .iter()
            .filter(|(bound, _)| bound == root)
            .collect::<Vec<_>>();
        match explicit.as_slice() {
            [] => {}
            [(_, path)] => return self.resolve_import_path(scope, path),
            _ => return None,
        }
        let mut wildcard = None;
        for prefix in &scope.wildcard_imports {
            let candidate = qualify(
                &self.resolve_import_path(scope, prefix)?,
                &[root.to_owned()],
            );
            if self.knows(&candidate) {
                if wildcard.as_ref().is_some_and(|bound| bound != &candidate) {
                    return None;
                }
                wildcard = Some(candidate);
            }
        }
        if wildcard.is_some() {
            return wildcard;
        }
        scope
            .package_prefixes
            .iter()
            .rev()
            .map(|package| qualify(package, &[root.to_owned()]))
            .chain([root.to_owned(), qualify("scala", &[root.to_owned()])])
            .find(|candidate| self.knows(candidate))
    }

    /// An import path is resolved from the importing package outward, then
    /// as written from the root.
    fn resolve_import_path(
        &self,
        scope: &ScalaArtifactTypeScope,
        path: &[String],
    ) -> Option<String> {
        let (root, rest) = path.split_first()?;
        let root = scope
            .package_prefixes
            .iter()
            .rev()
            .map(|package| qualify(package, std::slice::from_ref(root)))
            .chain([root.clone()])
            .find(|candidate| self.knows(candidate))?;
        let qualified = qualify(&root, rest);
        self.knows(&qualified).then_some(qualified)
    }
}

fn qualify(prefix: &str, rest: &[String]) -> String {
    std::iter::once(prefix)
        .filter(|prefix| !prefix.is_empty())
        .chain(rest.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(".")
}

/// One base class of a Scala linearization: an artifact type, or a parent
/// whose spelled name this artifact cannot resolve. Each unresolved parent is
/// its own base, so it is never deduplicated against another.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LinearBase {
    Type(String),
    Unresolved(usize),
}

/// One parent edge: the resolved parent, or `None`, with the type arguments
/// the child applies to it.
type ParentEdge = (Option<String>, Vec<ScalaTypeExpressionPath>);

/// The linearization `L(C) = C, L(Tn) +> ... +> L(T1)` (SLS 5.1.2), where
/// `a +> b` keeps the elements of `a` absent from `b`, followed by `b`.
///
/// The walk is iterative and memoized per type. A cycle, an oversized
/// closure, or a type without a scope returns `None`.
fn linearization(
    root: &str,
    parents_of: &impl Fn(&str) -> Option<Vec<ParentEdge>>,
) -> Option<Vec<LinearBase>> {
    let mut memo: HashMap<String, Vec<LinearBase>> = HashMap::default();
    let mut in_progress = HashSet::default();
    let mut unresolved = 0usize;
    let mut stack = vec![(root.to_owned(), false)];
    while let Some((current, expanded)) = stack.pop() {
        if memo.contains_key(&current) {
            continue;
        }
        let parents = parents_of(&current)?;
        if !expanded {
            if !in_progress.insert(current.clone()) {
                return None;
            }
            stack.push((current, true));
            for (parent, _) in &parents {
                let Some(parent) = parent else {
                    continue;
                };
                if in_progress.contains(parent) {
                    return None;
                }
                if !memo.contains_key(parent) {
                    stack.push((parent.clone(), false));
                }
            }
            continue;
        }
        let mut accumulated = Vec::<LinearBase>::new();
        for (parent, _) in &parents {
            let parent_bases = match parent {
                Some(parent) => memo.get(parent)?.clone(),
                None => {
                    unresolved += 1;
                    vec![LinearBase::Unresolved(unresolved)]
                }
            };
            let mut merged = parent_bases
                .into_iter()
                .filter(|base| !accumulated.contains(base))
                .collect::<Vec<_>>();
            merged.append(&mut accumulated);
            accumulated = merged;
        }
        accumulated.insert(0, LinearBase::Type(current.clone()));
        if accumulated.len() > MAX_LINEARIZATION_BASES {
            return None;
        }
        in_progress.remove(&current);
        memo.insert(current, accumulated);
    }
    memo.remove(root)
}

/// The members, contracts and diagnostics this module adds to one exact
/// scala-library production.
pub(super) struct ScalaCollectionProducts {
    pub(super) members: Vec<MemberFact>,
    pub(super) flows: Vec<CollectionFlowFact>,
    /// Existing members this artifact proves are the only callable of their
    /// family (owner, name, receiver form and arity). A scala-library pack is
    /// globally partial, and the overlay binds a call to a partial owner only
    /// through a complete family.
    pub(super) complete_families: Vec<String>,
}

pub(super) fn scala_standard_collection_contracts(
    types: &[TypeFact],
    members: &[MemberFact],
    scopes: &[ScalaArtifactTypeScope],
    diagnostics: &mut BoundedProducerDiagnostics,
) -> ScalaCollectionProducts {
    let mut products = ScalaCollectionProducts {
        members: Vec::new(),
        flows: Vec::new(),
        complete_families: Vec::new(),
    };
    let names = ArtifactNames::new(types, scopes);
    let Some(map) = names
        .types
        .get(SCALA_MUTABLE_MAP)
        .copied()
        .filter(|fact| fact.type_kind == TypeKind::Trait && fact.type_parameters.len() == 2)
    else {
        return products;
    };
    let mut unproven = Vec::new();

    // `Map` declares the protocol only in a reduced artifact; the real library
    // inherits it. Either way it describes the declared receiver type, which
    // any implementation may override, so its contracts are partial.
    for (name, arity) in MAP_PROTOCOL {
        let declared = members
            .iter()
            .find(|member| is_protocol_member(member, &map.id, name, arity));
        let member = match declared {
            Some(member) => member.clone(),
            None => match inherited_member(&names, scopes, members, map, name, arity) {
                Ok(member) => {
                    products.members.push(member.clone());
                    member
                }
                Err(reason) => {
                    unproven.push(format!("{SCALA_MUTABLE_MAP}.{name}: {reason}"));
                    continue;
                }
            },
        };
        if let Some(flow) = protocol_flow(&member, map, Completeness::Partial) {
            products.flows.push(flow);
        }
    }

    // `HashMap` is the one runtime class the `Map` factory proves, and it
    // overrides each protocol member, so its own declarations carry the
    // complete contracts.
    match names
        .types
        .get(SCALA_MUTABLE_HASH_MAP)
        .copied()
        .filter(|fact| fact.type_kind == TypeKind::Class && fact.type_parameters.len() == 2)
    {
        Some(hash_map) => {
            for (name, arity) in MAP_PROTOCOL {
                match sole_family_member(members, &hash_map.id, name, arity).and_then(|member| {
                    Some((
                        member,
                        protocol_flow(member, hash_map, Completeness::Complete)?,
                    ))
                }) {
                    Some((member, flow)) => {
                        products.complete_families.push(member.id.clone());
                        products.flows.push(flow);
                    }
                    None => unproven.push(format!("{SCALA_MUTABLE_HASH_MAP}.{name}")),
                }
            }
            match map_factory_member(&names, scopes, members, map, hash_map) {
                Some(factory) => products.members.push(factory),
                None => unproven.push(format!("{SCALA_MUTABLE_MAP}.apply factory")),
            }
        }
        None => unproven.push(SCALA_MUTABLE_HASH_MAP.to_owned()),
    }
    if !unproven.is_empty() {
        diagnostics.warning(
            "scala.collection_flow.unproven",
            None,
            format!(
                "Scala standard-library collection contracts were withheld because the artifact does not prove these declarations: {unproven:?}"
            ),
        );
    }
    products
        .flows
        .sort_unstable_by(|left, right| left.callable.cmp(&right.callable));
    products
}

/// The one instance method `owner` declares with `name` and `arity`, when
/// every instance method of that name has a signature to count, so none can
/// be an unseen overload of the same family.
fn sole_family_member<'facts>(
    members: &'facts [MemberFact],
    owner: &str,
    name: &str,
    arity: usize,
) -> Option<&'facts MemberFact> {
    let named = members
        .iter()
        .filter(|member| member.owner == owner && member.name == name && !member.is_static)
        .collect::<Vec<_>>();
    if named.iter().any(|member| member.signature.is_none()) {
        return None;
    }
    match named
        .into_iter()
        .filter(|member| is_protocol_member(member, owner, name, arity))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [member] => Some(*member),
        _ => None,
    }
}

fn is_protocol_member(member: &MemberFact, owner: &str, name: &str, arity: usize) -> bool {
    member.owner == owner
        && member.name == name
        && member.member_kind == MemberKind::Method
        && !member.is_static
        && member
            .signature
            .as_ref()
            .is_some_and(|signature| signature.parameters.len() == arity)
}

fn protocol_flow(
    member: &MemberFact,
    owner: &TypeFact,
    coverage: Completeness,
) -> Option<CollectionFlowFact> {
    let [key, value] = owner.type_parameters.as_slice() else {
        return None;
    };
    let signature = member.signature.as_ref()?;
    let substitution = CsmiCollectionFlowSubstitution::ReceiverArguments {
        declaration: owner.id.clone(),
    };
    let shape = keyed_shape(key, value);
    let payload = match member.name.as_str() {
        "apply" if is_map_apply_signature(signature, key, value) => {
            map_apply_flow(member, substitution, shape, value)
        }
        "update" if is_map_update_signature(signature, key, value) => {
            map_update_flow(member, substitution, shape, value)
        }
        "foreach" if is_map_foreach_signature(signature, key, value) => {
            map_foreach_flow(member, substitution, shape, key, value)
        }
        _ => return None,
    };
    Some(CollectionFlowFact {
        callable: member.id.clone(),
        payload,
        coverage: Some(coverage),
        provenance: Vec::new(),
    })
}

/// The member `map` inherits for one protocol name, published on `map` with
/// its signature substituted into `map`'s own type parameters, or why the
/// artifact does not prove it.
///
/// The declaring base is the first one in `map`'s linearization that declares
/// the name at this arity. Every base before it must be resolved, because an
/// unresolved parent could declare the overriding member; every path to the
/// declaring base must bind the type parameters its signature uses the same
/// way.
fn inherited_member(
    names: &ArtifactNames<'_>,
    scopes: &[ScalaArtifactTypeScope],
    members: &[MemberFact],
    map: &TypeFact,
    name: &str,
    arity: usize,
) -> Result<MemberFact, String> {
    let scopes_by_type = scopes
        .iter()
        .filter(|scope| !scope.module)
        .map(|scope| (scope.name.as_str(), scope))
        .collect::<HashMap<_, _>>();
    // A parent this artifact declares without a scope -- a type alias such
    // as `scala.Cloneable = java.lang.Cloneable`, or a nested template --
    // has parents and members this module cannot read, so it is an
    // unresolved base like a name the artifact does not declare.
    let parents_of = |owner: &str| -> Option<Vec<ParentEdge>> {
        let scope = scopes_by_type.get(owner)?;
        Some(
            scope
                .supertypes
                .iter()
                .map(|path| {
                    (
                        names
                            .resolve_type(scope, &path.segments)
                            .filter(|parent| scopes_by_type.contains_key(parent.as_str())),
                        path.arguments.clone(),
                    )
                })
                .collect(),
        )
    };
    let bases = linearization(&map.name, &parents_of)
        .ok_or_else(|| format!("{} has no bounded, acyclic linearization", map.name))?;
    let mut declared = None;
    let mut unresolved_before = false;
    for base in &bases {
        match base {
            LinearBase::Unresolved(_) => unresolved_before = true,
            LinearBase::Type(owner) => {
                let Some(owner) = names.types.get(owner.as_str()) else {
                    continue;
                };
                let candidates = members
                    .iter()
                    .filter(|member| is_protocol_member(member, &owner.id, name, arity))
                    .collect::<Vec<_>>();
                match candidates.as_slice() {
                    [] => continue,
                    [member] => declared = Some((*owner, *member)),
                    _ => return Err(format!("{} overloads {name}/{arity}", owner.name)),
                }
                break;
            }
        }
    }
    let (declaring, member) =
        declared.ok_or_else(|| format!("no base of {} declares {name}/{arity}", map.name))?;
    if unresolved_before {
        return Err(format!(
            "a parent this artifact cannot read precedes {} in the linearization of {}",
            declaring.name, map.name
        ));
    }
    let signature = member
        .signature
        .as_ref()
        .expect("protocol members carry a signature");
    let environments = instantiations(names, &scopes_by_type, map, &declaring.name)
        .ok_or_else(|| format!("{} binds no instantiation of {}", map.name, declaring.name))?;
    let mut substituted = None;
    for environment in &environments {
        let candidate = substitute_signature(signature, &declaring.type_parameters, environment)
            .ok_or_else(|| format!("{}.{name} has an unsubstitutable signature", declaring.name))?;
        if substituted
            .as_ref()
            .is_some_and(|previous: &Signature| previous != &candidate)
        {
            return Err(format!(
                "{} reaches {} with conflicting type arguments",
                map.name, declaring.name
            ));
        }
        substituted = Some(candidate);
    }
    let signature = substituted.expect("an instantiation was found");
    let parameter_types = signature
        .parameters
        .iter()
        .map(|parameter| parameter.r#type.clone())
        .collect::<Vec<_>>();
    let parameter_variadics = signature
        .parameters
        .iter()
        .map(|parameter| parameter.variadic)
        .collect::<Vec<_>>();
    let mut projected = member.clone();
    projected.id = member_declaration_id(MemberIdentity {
        owner_id: &map.id,
        kind: member.member_kind,
        is_static: false,
        parameter_arity: signature.parameters.len(),
        name: &member.name,
        generic_arity: signature.type_parameters.len(),
        parameter_types: &parameter_types,
        parameter_variadics: &parameter_variadics,
        return_type: signature.returns.as_ref(),
    });
    projected.owner = map.id.clone();
    projected.is_virtual = true;
    projected.receiver = Some(ReceiverFact { pointer: false });
    projected.signature = Some(signature);
    Ok(projected)
}

/// Every binding of `target`'s type parameters, in `root`'s terms, along each
/// parent path from `root`.
fn instantiations(
    names: &ArtifactNames<'_>,
    scopes_by_type: &HashMap<&str, &ScalaArtifactTypeScope>,
    root: &TypeFact,
    target: &str,
) -> Option<Vec<Vec<TypeRef>>> {
    let identity = root
        .type_parameters
        .iter()
        .map(|name| TypeRef::TypeParameter { name: name.clone() })
        .collect::<Vec<_>>();
    let mut seen = HashSet::default();
    let mut found = Vec::new();
    let mut pending = vec![(root.name.clone(), identity)];
    while let Some((owner, environment)) = pending.pop() {
        if seen.len() > MAX_LINEARIZATION_BASES {
            return None;
        }
        if !seen.insert((owner.clone(), environment.clone())) {
            continue;
        }
        if owner == target {
            found.push(environment);
            continue;
        }
        let (Some(scope), Some(fact)) = (
            scopes_by_type.get(owner.as_str()),
            names.types.get(owner.as_str()),
        ) else {
            continue;
        };
        for path in &scope.supertypes {
            let Some(parent) = names.resolve_type(scope, &path.segments) else {
                continue;
            };
            let parent_parameters = &names.types.get(parent.as_str())?.type_parameters;
            let arguments = (0..parent_parameters.len())
                .map(|index| {
                    let Some(argument) = path.arguments.get(index) else {
                        return Some(TypeRef::Unknown);
                    };
                    substitute(
                        &super::scala_artifact::scala_type_ref(argument, &fact.type_parameters),
                        &fact.type_parameters,
                        &environment,
                        &[],
                        0,
                    )
                })
                .collect::<Option<Vec<_>>>()?;
            pending.push((parent, arguments));
        }
    }
    (!found.is_empty()).then_some(found)
}

fn substitute_signature(
    signature: &Signature,
    parameters: &[String],
    environment: &[TypeRef],
) -> Option<Signature> {
    let shadowed = signature.type_parameters.as_slice();
    Some(Signature {
        type_parameters: signature.type_parameters.clone(),
        parameters: signature
            .parameters
            .iter()
            .map(|parameter| {
                Some(Parameter {
                    r#type: substitute(&parameter.r#type, parameters, environment, shadowed, 0)?,
                    ..parameter.clone()
                })
            })
            .collect::<Option<Vec<_>>>()?,
        returns: match &signature.returns {
            Some(returns) => Some(substitute(returns, parameters, environment, shadowed, 0)?),
            None => None,
        },
    })
}

/// Replace `parameters` by `environment` in a type reference. A method type
/// parameter that shadows an owner parameter keeps its name. A reference form
/// this producer does not emit returns `None`.
fn substitute(
    reference: &TypeRef,
    parameters: &[String],
    environment: &[TypeRef],
    shadowed: &[String],
    depth: usize,
) -> Option<TypeRef> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let arguments = |arguments: &[TypeRef]| {
        arguments
            .iter()
            .map(|argument| substitute(argument, parameters, environment, shadowed, depth + 1))
            .collect::<Option<Vec<_>>>()
    };
    Some(match reference {
        TypeRef::TypeParameter { name } if !shadowed.contains(name) => {
            match parameters.iter().position(|parameter| parameter == name) {
                Some(index) => environment.get(index)?.clone(),
                None => reference.clone(),
            }
        }
        TypeRef::TypeParameter { .. } | TypeRef::Unknown => reference.clone(),
        TypeRef::Named {
            name,
            arguments: written,
            nullable,
        } => TypeRef::Named {
            name: name.clone(),
            arguments: arguments(written)?,
            nullable: *nullable,
        },
        TypeRef::Declared {
            id,
            arguments: written,
            nullable,
        } => TypeRef::Declared {
            id: id.clone(),
            arguments: arguments(written)?,
            nullable: *nullable,
        },
        _ => return None,
    })
}

/// The static factory `mutable.Map[K, V](elems*)`, whose runtime result is
/// exactly `HashMap[K, V]`.
///
/// The proof is structural: `object Map extends
/// MapFactory.Delegate[Map](HashMap)` with neither object declaring its own
/// `apply`, `MapFactory.Delegate.apply(elems*)` forwarding to the delegate,
/// and `object HashMap extends MapFactory[HashMap]`, whose inherited `apply`
/// builds through its own `from`.
fn map_factory_member(
    names: &ArtifactNames<'_>,
    scopes: &[ScalaArtifactTypeScope],
    members: &[MemberFact],
    map: &TypeFact,
    hash_map: &TypeFact,
) -> Option<MemberFact> {
    let module_scope = |name: &str| {
        scopes
            .iter()
            .find(|scope| scope.module && scope.name == name)
    };
    let map_module = module_scope(SCALA_MUTABLE_MAP)?;
    let hash_map_module = module_scope(SCALA_MUTABLE_HASH_MAP)?;
    let delegate = map_module.parent_application.as_ref()?;
    let resolves_to = |scope, path: &[String], expected: &str| {
        names.resolve_type(scope, path).as_deref() == Some(expected)
    };
    let [type_argument] = delegate.type_arguments.as_slice() else {
        return None;
    };
    let [delegate_value] = delegate.value_arguments.as_slice() else {
        return None;
    };
    if !resolves_to(map_module, &delegate.parent, SCALA_MAP_FACTORY_DELEGATE)
        || !resolves_to(map_module, type_argument, SCALA_MUTABLE_MAP)
        || !resolves_to(map_module, delegate_value, SCALA_MUTABLE_HASH_MAP)
        || !names.modules.contains(SCALA_MUTABLE_HASH_MAP)
    {
        return None;
    }
    let hash_map_factory = hash_map_module.parent_application.as_ref()?;
    let [hash_map_argument] = hash_map_factory.type_arguments.as_slice() else {
        return None;
    };
    if !resolves_to(hash_map_module, &hash_map_factory.parent, SCALA_MAP_FACTORY)
        || !resolves_to(hash_map_module, hash_map_argument, SCALA_MUTABLE_HASH_MAP)
        || !hash_map_factory.value_arguments.is_empty()
    {
        return None;
    }
    let declares_static = |owner: &str, name: &str| {
        members
            .iter()
            .any(|member| member.owner == owner && member.is_static && member.name == name)
    };
    if declares_static(&map.id, "apply")
        || declares_static(&hash_map.id, "apply")
        || !declares_static(&hash_map.id, "from")
    {
        return None;
    }
    let delegate_type = names.types.get(SCALA_MAP_FACTORY_DELEGATE)?;
    let forwards = members.iter().any(|member| {
        member.owner == delegate_type.id
            && member.name == "apply"
            && !member.is_static
            && member.signature.as_ref().is_some_and(|signature| {
                matches!(signature.parameters.as_slice(), [parameter] if parameter.variadic)
            })
    });
    if !forwards {
        return None;
    }
    let [key, value] = map.type_parameters.as_slice() else {
        return None;
    };
    let type_parameter = |name: &String| TypeRef::TypeParameter { name: name.clone() };
    let entry = TypeRef::Named {
        name: "scala.Tuple2".to_owned(),
        arguments: vec![type_parameter(key), type_parameter(value)],
        nullable: false,
    };
    let returns = TypeRef::Named {
        name: SCALA_MUTABLE_MAP.to_owned(),
        arguments: vec![type_parameter(key), type_parameter(value)],
        nullable: false,
    };
    let signature = Signature {
        type_parameters: vec![key.clone(), value.clone()],
        parameters: vec![Parameter {
            name: Some("elems".to_owned()),
            r#type: entry.clone(),
            optional: false,
            variadic: true,
            passing_mode: Default::default(),
            role: None,
        }],
        returns: Some(returns.clone()),
    };
    let id = member_declaration_id(MemberIdentity {
        owner_id: &map.id,
        kind: MemberKind::Method,
        is_static: true,
        parameter_arity: 1,
        name: "apply",
        generic_arity: 2,
        parameter_types: &[entry],
        parameter_variadics: &[true],
        return_type: Some(&returns),
    });
    Some(MemberFact {
        implemented_trait: None,
        self_form: None,
        non_overridable: None,
        ambient_use: None,
        value_type: None,
        proxied_type: None,
        id,
        owner: map.id.clone(),
        name: "apply".to_owned(),
        member_kind: MemberKind::Method,
        visibility: map.visibility,
        is_static: true,
        is_abstract: false,
        is_virtual: false,
        implicit_operation: None,
        explicit_operation: None,
        // `map_factory_member` refused a `Map` or `HashMap` object that
        // declares its own `apply`, so this is the only static `apply`.
        callable_family_complete: true,
        // A runtime class identity, not a return annotation: its type
        // arguments are the `returns` type's.
        exact_return_classes: vec![TypeRef::Declared {
            id: hash_map.id.clone(),
            arguments: Vec::new(),
            nullable: false,
        }],
        signature: Some(signature),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        guard: None,
        locator: map.locator.clone(),
    })
}

fn keyed_shape(key: &str, value: &str) -> CsmiCollectionFlowShape {
    CsmiCollectionFlowShape::Keyed {
        key: Box::new(collection_value_shape(key)),
        value: Box::new(collection_value_shape(value)),
        entry_components: Some(vec![
            CsmiCollectionFlowEntryComponent::Key,
            CsmiCollectionFlowEntryComponent::Value,
        ]),
    }
}

fn collection_value_shape(parameter: &str) -> CsmiCollectionFlowShape {
    brokk_bifrost_semantic::analyzer::semantic_model::csmi::collection_value_shape(&format!(
        "type-parameter.{parameter}"
    ))
}

fn is_map_apply_signature(signature: &Signature, key: &str, value: &str) -> bool {
    signature.parameters.len() == 1
        && signature.parameters[0].r#type.is_type_parameter(key)
        && signature
            .returns
            .as_ref()
            .is_some_and(|result| result.is_type_parameter(value))
}

fn is_map_update_signature(signature: &Signature, key: &str, value: &str) -> bool {
    signature.parameters.len() == 2
        && signature.parameters[0].r#type.is_type_parameter(key)
        && signature.parameters[1].r#type.is_type_parameter(value)
}

fn is_map_foreach_signature(signature: &Signature, key: &str, value: &str) -> bool {
    let Some(Parameter { r#type, .. }) = signature.parameters.first() else {
        return false;
    };
    let TypeRef::Named {
        name, arguments, ..
    } = r#type
    else {
        return false;
    };
    let Some(TypeRef::Named {
        name: tuple_name,
        arguments: tuple_arguments,
        ..
    }) = arguments.first()
    else {
        return false;
    };
    name == "scala.Function1"
        && tuple_name == "scala.Tuple2"
        && tuple_arguments.len() == 2
        && tuple_arguments[0].is_type_parameter(key)
        && tuple_arguments[1].is_type_parameter(value)
}

fn map_apply_flow(
    member: &MemberFact,
    substitution: CsmiCollectionFlowSubstitution,
    receiver_shape: CsmiCollectionFlowShape,
    value_parameter: &str,
) -> CsmiCollectionFlowPayload {
    let mut source_projection =
        brokk_bifrost_semantic::analyzer::semantic_model::csmi::entry_parameter_projection(0);
    source_projection.steps.push(CsmiProjectionStep {
        kind: "entry-value".to_owned(),
        args: None,
    });
    CsmiCollectionFlowPayload {
        kind: CsmiCollectionFlowKind::CollectionFlow,
        callable: member.id.clone(),
        receiver_substitution: Some(substitution),
        roots: vec![
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(input_receiver_root()),
                shape: receiver_shape,
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Output(CsmiOutputBoundaryRoot::Result(
                    CsmiOutputResultRoot {
                        phase: CsmiOutputPhase::Output,
                        role: CsmiResultRootRole::Result,
                        position: 0,
                    },
                )),
                shape: collection_value_shape(value_parameter),
            },
        ],
        transfers: vec![CsmiCollectionFlowTransfer {
            source: CsmiInputLocation {
                root: input_receiver_root(),
                projection: Some(source_projection),
            },
            destination: CsmiOutputLocation {
                root: CsmiOutputBoundaryRoot::Result(CsmiOutputResultRoot {
                    phase: CsmiOutputPhase::Output,
                    role: CsmiResultRootRole::Result,
                    position: 0,
                }),
                projection: None,
            },
        }],
        invocations: Vec::new(),
    }
}

fn map_update_flow(
    member: &MemberFact,
    substitution: CsmiCollectionFlowSubstitution,
    receiver_shape: CsmiCollectionFlowShape,
    value_parameter: &str,
) -> CsmiCollectionFlowPayload {
    let mut destination_projection =
        brokk_bifrost_semantic::analyzer::semantic_model::csmi::entry_parameter_projection(0);
    destination_projection.steps.push(CsmiProjectionStep {
        kind: "entry-value".to_owned(),
        args: None,
    });
    CsmiCollectionFlowPayload {
        kind: CsmiCollectionFlowKind::CollectionFlow,
        callable: member.id.clone(),
        receiver_substitution: Some(substitution),
        roots: vec![
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(input_receiver_root()),
                shape: receiver_shape.clone(),
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(CsmiInputBoundaryRoot::Parameter(
                    CsmiInputParameterRoot {
                        phase: CsmiInputPhase::Input,
                        role: CsmiParameterRootRole::Parameter,
                        position: 1,
                    },
                )),
                shape: collection_value_shape(value_parameter),
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Output(output_receiver_root()),
                shape: receiver_shape,
            },
        ],
        transfers: vec![CsmiCollectionFlowTransfer {
            source: CsmiInputLocation {
                root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                    phase: CsmiInputPhase::Input,
                    role: CsmiParameterRootRole::Parameter,
                    position: 1,
                }),
                projection: None,
            },
            destination: CsmiOutputLocation {
                root: output_receiver_root(),
                projection: Some(destination_projection),
            },
        }],
        invocations: Vec::new(),
    }
}

fn map_foreach_flow(
    member: &MemberFact,
    substitution: CsmiCollectionFlowSubstitution,
    receiver_shape: CsmiCollectionFlowShape,
    key_parameter: &str,
    value_parameter: &str,
) -> CsmiCollectionFlowPayload {
    CsmiCollectionFlowPayload {
        kind: CsmiCollectionFlowKind::CollectionFlow,
        callable: member.id.clone(),
        receiver_substitution: Some(substitution),
        roots: vec![
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(input_receiver_root()),
                shape: receiver_shape,
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(CsmiInputBoundaryRoot::Parameter(
                    CsmiInputParameterRoot {
                        phase: CsmiInputPhase::Input,
                        role: CsmiParameterRootRole::Parameter,
                        position: 0,
                    },
                )),
                shape: CsmiCollectionFlowShape::Value {
                    r#type: CsmiTypeExpression::Intrinsic(CsmiIntrinsicType {
                        kind: CsmiIntrinsicTypeKind::Intrinsic,
                        vocabulary: "ai.brokk.csmi.jvm-symbol".to_owned(),
                        version: "0.1".to_owned(),
                        identifier: "scala.Function1".to_owned(),
                    }),
                },
            },
        ],
        transfers: Vec::new(),
        invocations: vec![CsmiCollectionFlowInvocation {
            callback: CsmiInputLocation {
                root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                    phase: CsmiInputPhase::Input,
                    role: CsmiParameterRootRole::Parameter,
                    position: 0,
                }),
                projection: None,
            },
            parameters: vec![CsmiCollectionFlowShape::Product {
                components: vec![
                    collection_value_shape(key_parameter),
                    collection_value_shape(value_parameter),
                ],
            }],
            arguments: vec![
                brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowArgument {
                    source: CsmiInputLocation {
                        root: input_receiver_root(),
                        projection: Some(entry_all_projection()),
                    },
                    parameter: 0,
                },
            ],
            timing: CsmiCollectionFlowTiming::DuringCall,
        }],
    }
}

fn input_receiver_root() -> CsmiInputBoundaryRoot {
    CsmiInputBoundaryRoot::Receiver(CsmiInputReceiverRoot {
        phase: CsmiInputPhase::Input,
        role: CsmiReceiverRootRole::Receiver,
    })
}

fn output_receiver_root() -> CsmiOutputBoundaryRoot {
    CsmiOutputBoundaryRoot::Receiver(CsmiOutputReceiverRoot {
        phase: CsmiOutputPhase::Output,
        role: CsmiReceiverRootRole::Receiver,
    })
}

fn entry_all_projection() -> CsmiProjection {
    CsmiProjection {
        scheme: "csmi.collection-flow".to_owned(),
        scheme_version: "0.1.0".to_owned(),
        steps: vec![CsmiProjectionStep {
            kind: "entry".to_owned(),
            args: Some(serde_json::json!({"key": {"kind": "all"}})),
        }],
    }
}
