//! JVM owner inventories for a Scala source artifact.
//!
//! A Scala source JAR publishes one owner per top-level type name: a class or
//! trait and its companion `object` share the name, with the object's members
//! static, as scalac's static forwarders present them on the JVM. An owner
//! inventory claims that the published members are every term the owner has
//! and that its supertypes are named exactly; without one, lookup keeps the
//! owner open (`OwnerInventoryOpen`).
//!
//! The claim is made only from structure this producer reads:
//!
//! - Terms are complete when every `def`, `val` and constructor of both sides
//!   was emitted with a signature, non-API members included as
//!   `additional_members`. Case classes and enums synthesize members, a `var`
//!   has a setter, an implicit class adds a conversion and an `export` clause
//!   adds aliases; none of those is published, so such an owner stays open.
//!   A nested owner has no resolved scope and stays open.
//! - An `object`'s inherited terms are its own: they are published as static
//!   forwarders of the owner. Every base of the object's linearization must be
//!   a declaration of this artifact with complete terms and no type
//!   parameters; otherwise the static side, and with it the owner, stays open.
//! - Supertypes are the class side's declared parents resolved to qualified
//!   names (following type aliases this artifact declares), plus
//!   `java.lang.Object`, the JVM superclass every Scala class reaches.
//! - Nested types are not enumerated, so a type that declares one claims no
//!   type namespace.

use super::scala_collection_contracts::{
    ArtifactNames, LinearBase, ParentEdge, ScalaArtifactTypeScope, linearization,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    HierarchyFact, HierarchyKind, JvmOwnerInventory, MemberFact, MemberKind, TypeFact, TypeKind,
    TypeRef, Visibility,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_semantic::analyzer::semantic_model::identity::{
    MemberIdentity, member_declaration_id,
};

/// Bound on the alias chain one supertype follows.
const MAX_ALIAS_DEPTH: usize = 8;

/// What the declaration walk proved about one side of one owner: a class or
/// trait, or an `object`. Both sides of a companion pair share `owner_id`.
#[derive(Debug)]
pub(super) struct ScalaOwnerSide {
    pub(super) owner_id: String,
    pub(super) module: bool,
    /// Whether some term of this side was not emitted with its signature, or
    /// the side synthesizes terms this producer does not publish.
    pub(super) terms_open: bool,
    pub(super) declares_types: bool,
    /// The resolution scope of a top-level declaration; nested sides have none.
    pub(super) scope: Option<ScalaArtifactTypeScope>,
}

/// Where the types one owner's member signatures spell are resolved: the
/// scope of its top-level declaration, and the simple names a nested template
/// of the same compilation unit declares or imports, which may shadow it.
#[derive(Debug)]
pub(super) struct ScalaSignatureScope {
    pub(super) owner_id: String,
    pub(super) scope: ScalaArtifactTypeScope,
    pub(super) shadowed: HashSet<String>,
    /// A nested wildcard import may shadow any simple name.
    pub(super) shadows_all: bool,
}

/// A type alias this artifact declares at top level, with the path it names
/// and the scope that path is written in.
#[derive(Debug)]
pub(super) struct ScalaArtifactAlias {
    pub(super) name: String,
    pub(super) target: Vec<String>,
    pub(super) scope: ScalaArtifactTypeScope,
}

/// The facts one artifact production assembled, before inventories.
pub(super) struct ScalaInventoryInputs<'facts> {
    /// Published owners, inventoried in place.
    pub(super) types: &'facts mut [TypeFact],
    /// Published members; static forwarders are appended.
    pub(super) members: &'facts mut Vec<MemberFact>,
    /// Owners and members outside the API projection: they bind names and
    /// supply inherited terms, but are not published.
    pub(super) hidden_types: &'facts [TypeFact],
    pub(super) hidden_members: &'facts [MemberFact],
    /// Non-API members of published owners, by owner id.
    pub(super) additional_members: HashMap<String, Vec<MemberFact>>,
    pub(super) sides: &'facts [ScalaOwnerSide],
    pub(super) aliases: &'facts [ScalaArtifactAlias],
    pub(super) signature_scopes: &'facts [ScalaSignatureScope],
    /// Owners that received members this module did not read from source.
    pub(super) synthesized_owners: &'facts HashSet<String>,
}

/// Qualify the type names member signatures spell, attach a
/// [`JvmOwnerInventory`] to every published owner and publish the static
/// forwarders of its `object` side. Each forwarder or additional
/// member is a record; when `take_record` refuses one, every inventory stays
/// open.
pub(super) fn attach_scala_owner_inventories(
    inputs: ScalaInventoryInputs<'_>,
    mut take_record: impl FnMut() -> bool,
) {
    let ScalaInventoryInputs {
        types,
        members,
        hidden_types,
        hidden_members,
        mut additional_members,
        sides,
        aliases,
        signature_scopes,
        synthesized_owners,
    } = inputs;
    let all_types = types
        .iter()
        .chain(hidden_types)
        .cloned()
        .collect::<Vec<_>>();
    let scopes = sides
        .iter()
        .filter_map(|side| side.scope.as_ref())
        .chain(aliases.iter().map(|alias| &alias.scope))
        .collect::<Vec<_>>();
    let names = ArtifactNames::from_facts(&all_types, scopes.iter().copied());
    let signature_scopes_by_owner = signature_scopes
        .iter()
        .map(|scope| (scope.owner_id.as_str(), scope))
        .collect::<HashMap<_, _>>();
    let aliases_by_name = aliases
        .iter()
        .map(|alias| (alias.name.as_str(), alias))
        .collect::<HashMap<_, _>>();
    let qualify = |member: &mut MemberFact| {
        if let (Some(scope), Some(signature)) = (
            signature_scopes_by_owner.get(member.owner.as_str()),
            member.signature.as_mut(),
        ) {
            for parameter in &mut signature.parameters {
                qualify_type(&names, &aliases_by_name, scope, &mut parameter.r#type);
            }
            if let Some(returns) = &mut signature.returns {
                qualify_type(&names, &aliases_by_name, scope, returns);
            }
        }
    };
    members.iter_mut().for_each(qualify);
    additional_members.values_mut().flatten().for_each(qualify);
    let hidden_members = hidden_members
        .iter()
        .cloned()
        .map(|mut member| {
            qualify(&mut member);
            member
        })
        .collect::<Vec<_>>();
    let hidden_members = hidden_members.as_slice();
    let sides_by_owner = {
        let mut sides_by_owner = HashMap::<&str, Vec<&ScalaOwnerSide>>::default();
        for side in sides {
            sides_by_owner.entry(&side.owner_id).or_default().push(side);
        }
        sides_by_owner
    };
    let class_scopes = sides
        .iter()
        .filter(|side| !side.module)
        .filter_map(|side| side.scope.as_ref())
        .map(|scope| (scope.name.as_str(), scope))
        .collect::<HashMap<_, _>>();
    let id_by_name = all_types
        .iter()
        .map(|fact| (fact.name.as_str(), fact.id.as_str()))
        .collect::<HashMap<_, _>>();
    let parameterless = all_types
        .iter()
        .filter(|fact| fact.type_parameters.is_empty())
        .map(|fact| fact.id.as_str())
        .collect::<HashSet<_>>();
    let open_terms = sides
        .iter()
        .filter(|side| side.terms_open)
        .map(|side| side.owner_id.as_str())
        .chain(synthesized_owners.iter().map(String::as_str))
        .collect::<HashSet<_>>();
    let mut instance_terms = HashMap::<&str, Vec<&MemberFact>>::default();
    for member in members
        .iter()
        .chain(hidden_members)
        .chain(additional_members.values().flatten())
    {
        if !member.is_static && member.member_kind != MemberKind::Constructor {
            instance_terms
                .entry(&member.owner)
                .or_default()
                .push(member);
        }
    }
    let mut records_complete = true;
    let mut forwarders = Vec::new();
    let mut inventories = Vec::with_capacity(types.len());
    let mut inventoried = HashSet::default();
    for owner in types.iter() {
        if owner.type_kind == TypeKind::TypeAlias {
            inventories.push(None);
            continue;
        }
        // Two entries that declare one name are two owners the store cannot
        // tell apart; only the first is enumerated, and neither is closed.
        let repeated = !inventoried.insert(owner.id.as_str());
        let owner_sides = if repeated {
            &[][..]
        } else {
            sides_by_owner
                .get(owner.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default()
        };
        let mut terms_complete = !owner_sides.is_empty()
            && !open_terms.contains(owner.id.as_str())
            && owner_sides.iter().all(|side| side.scope.is_some());
        let types_complete = !repeated && owner_sides.iter().all(|side| !side.declares_types);
        let mut supertypes = Vec::new();
        let mut supertypes_complete = !repeated;
        for side in owner_sides.iter().filter(|side| !side.module) {
            let Some(scope) = &side.scope else {
                supertypes_complete = false;
                continue;
            };
            for path in &scope.supertypes {
                match resolve_parent(&names, &aliases_by_name, scope, &path.segments) {
                    Some(name) => supertypes.push(HierarchyFact {
                        hierarchy_kind: HierarchyKind::Extends,
                        target: TypeRef::named(name),
                        declaration_ordinal: None,
                    }),
                    None => supertypes_complete = false,
                }
            }
        }
        if !supertypes
            .iter()
            .any(|parent| matches!(&parent.target, TypeRef::Named { name, .. } if name == "java.lang.Object"))
        {
            supertypes.push(HierarchyFact {
                hierarchy_kind: HierarchyKind::Extends,
                target: TypeRef::named("java.lang.Object"),
                declaration_ordinal: None,
            });
        }
        for side in owner_sides.iter().filter(|side| side.module) {
            let Some(scope) = &side.scope else {
                continue;
            };
            let mut declared = TermKeys::default();
            for member in members
                .iter()
                .chain(additional_members.get(&owner.id).into_iter().flatten())
                .filter(|member| member.owner == owner.id && member.is_static)
            {
                declared.insert(member);
            }
            match module_forwarders(
                owner,
                scope,
                &names,
                &class_scopes,
                &id_by_name,
                &parameterless,
                &open_terms,
                &instance_terms,
                declared,
            ) {
                Some(mut owned) => forwarders.append(&mut owned),
                None => terms_complete = false,
            }
        }
        inventories.push(Some(JvmOwnerInventory {
            enclosing_type_parameters: Vec::new(),
            callables_complete: terms_complete,
            values_complete: terms_complete,
            types_complete,
            supertypes_complete,
            supertypes,
            nested_types: Vec::new(),
            additional_members: Vec::new(),
        }));
    }
    for forwarder in forwarders {
        if !take_record() {
            records_complete = false;
            break;
        }
        // A protected or qualified-private term of a base is reachable only
        // from inside the object or its package, so it is not public API.
        if forwarder.visibility == Visibility::Public {
            members.push(forwarder);
        } else {
            additional_members
                .entry(forwarder.owner.clone())
                .or_default()
                .push(forwarder);
        }
    }
    for (owner, inventory) in types.iter_mut().zip(inventories) {
        let Some(mut inventory) = inventory else {
            continue;
        };
        let mut additional = additional_members.remove(&owner.id).unwrap_or_default();
        additional
            .sort_unstable_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
        for member in additional {
            if !take_record() {
                records_complete = false;
                break;
            }
            inventory.additional_members.push(member);
        }
        owner.jvm_inventory = Some(inventory);
    }
    if !records_complete {
        for inventory in types
            .iter_mut()
            .filter_map(|owner| owner.jvm_inventory.as_mut())
        {
            inventory.callables_complete = false;
            inventory.values_complete = false;
            inventory.types_complete = false;
        }
    }
}

/// The qualified name of a written parent, following aliases this artifact
/// declares without type parameters.
fn resolve_parent(
    names: &ArtifactNames<'_>,
    aliases: &HashMap<&str, &ScalaArtifactAlias>,
    scope: &ScalaArtifactTypeScope,
    segments: &[String],
) -> Option<String> {
    resolve_alias(names, aliases, names.resolve_named_type(scope, segments)?)
}

/// The type a qualified name denotes once artifact aliases without type
/// parameters are followed, or `None` when an alias cannot be followed.
fn resolve_alias(
    names: &ArtifactNames<'_>,
    aliases: &HashMap<&str, &ScalaArtifactAlias>,
    mut resolved: String,
) -> Option<String> {
    for _ in 0..MAX_ALIAS_DEPTH {
        let Some(fact) = names.types.get(resolved.as_str()) else {
            return Some(resolved);
        };
        if fact.type_kind != TypeKind::TypeAlias {
            return Some(resolved);
        }
        let alias = aliases.get(resolved.as_str())?;
        if !fact.type_parameters.is_empty() {
            return None;
        }
        resolved = names.resolve_named_type(&alias.scope, &alias.target)?;
    }
    None
}

/// Replace each written type path by the qualified name it resolves to,
/// through an alias without type parameters to the type it names, as
/// `type String = java.lang.String` erases. A path that does not resolve
/// keeps its spelling.
fn qualify_type(
    names: &ArtifactNames<'_>,
    aliases: &HashMap<&str, &ScalaArtifactAlias>,
    scope: &ScalaSignatureScope,
    reference: &mut TypeRef,
) {
    let mut pending = vec![reference];
    while let Some(reference) = pending.pop() {
        let TypeRef::Named {
            name, arguments, ..
        } = reference
        else {
            continue;
        };
        // `scala_type_ref` joined the parser's path segments with dots.
        let segments = name.split('.').map(str::to_owned).collect::<Vec<_>>();
        if !scope.shadows_all
            && !scope.shadowed.contains(&segments[0])
            && let Some(qualified) = names.resolve_named_type(&scope.scope, &segments)
        {
            *name = (arguments.is_empty())
                .then(|| resolve_alias(names, aliases, qualified.clone()))
                .flatten()
                .unwrap_or(qualified);
        }
        pending.extend(arguments.iter_mut());
    }
}

/// A term's kind and parameter types; `None` when the member has no signature.
type TermKey<'facts> = (MemberKind, Option<Vec<&'facts TypeRef>>);

/// The terms seen so far, identified by name, kind and parameter types.
#[derive(Default)]
struct TermKeys<'facts> {
    by_name: HashMap<&'facts str, Vec<TermKey<'facts>>>,
}

impl<'facts> TermKeys<'facts> {
    /// Record `member`'s term, returning whether it was new.
    fn insert(&mut self, member: &'facts MemberFact) -> bool {
        let key = (
            member.member_kind,
            member.signature.as_ref().map(|signature| {
                signature
                    .parameters
                    .iter()
                    .map(|parameter| &parameter.r#type)
                    .collect()
            }),
        );
        let seen = self.by_name.entry(&member.name).or_default();
        if seen.contains(&key) {
            return false;
        }
        seen.push(key);
        true
    }
}

/// The terms an `object` inherits, as static members of its owner, or `None`
/// when its linearization is not fully enumerated.
///
/// Bases are visited in linearization order, so the most derived declaration
/// of a term wins, and a term the object declares itself shadows every base.
#[allow(clippy::too_many_arguments)]
fn module_forwarders<'facts>(
    owner: &TypeFact,
    module_scope: &ScalaArtifactTypeScope,
    names: &ArtifactNames<'_>,
    class_scopes: &HashMap<&str, &ScalaArtifactTypeScope>,
    id_by_name: &HashMap<&str, &str>,
    parameterless: &HashSet<&str>,
    open_terms: &HashSet<&str>,
    instance_terms: &HashMap<&'facts str, Vec<&'facts MemberFact>>,
    mut seen: TermKeys<'facts>,
) -> Option<Vec<MemberFact>> {
    // The object is the root; its parents come from its own scope.
    const ROOT: &str = "";
    let parents_of = |name: &str| -> Option<Vec<ParentEdge>> {
        let scope = if name == ROOT {
            module_scope
        } else {
            class_scopes.get(name)?
        };
        Some(
            scope
                .supertypes
                .iter()
                .map(|path| {
                    (
                        names
                            .resolve_type(scope, &path.segments)
                            .filter(|parent| class_scopes.contains_key(parent.as_str())),
                        path.arguments.clone(),
                    )
                })
                .collect(),
        )
    };
    let bases = linearization(ROOT, &parents_of)?;
    let mut forwarders = Vec::new();
    for base in bases.iter().skip(1) {
        let LinearBase::Type(base) = base else {
            return None;
        };
        let base_id = *id_by_name.get(base.as_str())?;
        if open_terms.contains(base_id) || !parameterless.contains(base_id) {
            return None;
        }
        for member in instance_terms.get(base_id).into_iter().flatten() {
            if !seen.insert(member) {
                continue;
            }
            forwarders.push(static_forwarder(member, owner));
        }
    }
    Some(forwarders)
}

/// The static forwarder of an inherited instance term on `owner`, keeping the
/// declaring member's signature and source locator.
fn static_forwarder(member: &MemberFact, owner: &TypeFact) -> MemberFact {
    let parameter_types = member
        .signature
        .iter()
        .flat_map(|signature| &signature.parameters)
        .map(|parameter| parameter.r#type.clone())
        .collect::<Vec<_>>();
    let parameter_variadics = member
        .signature
        .iter()
        .flat_map(|signature| &signature.parameters)
        .map(|parameter| parameter.variadic)
        .collect::<Vec<_>>();
    let mut forwarder = member.clone();
    forwarder.id = member_declaration_id(MemberIdentity {
        owner_id: &owner.id,
        kind: member.member_kind,
        is_static: true,
        parameter_arity: parameter_types.len(),
        name: &member.name,
        generic_arity: member
            .signature
            .as_ref()
            .map_or(0, |signature| signature.type_parameters.len()),
        parameter_types: &parameter_types,
        parameter_variadics: &parameter_variadics,
        return_type: member
            .signature
            .as_ref()
            .and_then(|signature| signature.returns.as_ref()),
    });
    forwarder.owner = owner.id.clone();
    forwarder.is_static = true;
    forwarder.is_abstract = false;
    forwarder.is_virtual = false;
    forwarder.receiver = None;
    forwarder.callable_family_complete = false;
    forwarder
}
