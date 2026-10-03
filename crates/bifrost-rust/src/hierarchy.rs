use crate::graph_support::{
    RustCargoRouteError, RustFactSource, RustItemMacroDecided, RustPlacedDeclaration,
    is_rust_enum_declaration, is_rust_struct_declaration, is_rust_trait_declaration,
    is_rust_type_alias_declaration, live_file_at, resolve_imported_export_from_binder,
    resolve_module_files,
};
use crate::hierarchy_source_context::RustSourceContextIndex;
use crate::imports::{
    resolve_rust_module_path_with_crate, resolve_rust_module_segments_with_crate,
    rust_crate_root_package,
};
use crate::usage::exported_targets_from_files;
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustCallableSourceFact, RustDeclarationKind, RustGenericParameterSourceFact,
    RustImplSourceFact, RustItemBodyChildSourceFact, RustItemMacroExpansion,
    RustItemMacroSourceFact, RustItemMacroSourcePosition, RustItemSourceFacts, RustMacroTokenTree,
    RustSourceContextKind, RustTraitSourceFact, RustTypeSourceFact, RustTypeSourceShape,
    RustTypeWrapperSourceKind,
};
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclaration, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_utils::rel_path_string;
use std::mem::size_of;

/// The canonical, source-owned inputs to Rust hierarchy resolution for one
/// mounted file. These rows are content-addressed; `declaration_units` is the
/// placement-dependent bridge that retains every source declaration link to a
/// mounted `CodeUnit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustHierarchySourceFacts {
    pub items: RustItemSourceFacts,
    pub types: Vec<RustTypeSourceFact>,
    pub declarations: Vec<SourceDeclaration>,
    pub declaration_units: Vec<(SourceDeclarationId, CodeUnit)>,
    pub module_names: HashMap<SourceDeclarationId, String>,
    pub imports: Vec<SourceImportFact>,
}

impl RustHierarchySourceFacts {
    /// Heap bytes owned below this DTO, excluding inline fact storage but
    /// including the vector/map allocation slots and their heap strings. The
    /// result is used only as a bounded-cache weight, so it deliberately
    /// follows the source-fact estimate convention.
    pub fn estimated_retained_bytes(&self) -> usize {
        let declaration_units = self
            .declaration_units
            .iter()
            .map(|(_, unit)| {
                unit.fq_name().len()
                    + unit.signature().map_or(0, str::len)
                    + unit.source().rel_path().to_string_lossy().len()
            })
            .fold(0usize, usize::saturating_add);
        let module_names = self
            .module_names
            .values()
            .map(|name| name.capacity())
            .fold(0usize, usize::saturating_add);
        self.items
            .estimated_retained_bytes()
            .saturating_add(
                self.types
                    .capacity()
                    .saturating_mul(size_of::<RustTypeSourceFact>()),
            )
            .saturating_add(
                self.types
                    .iter()
                    .map(RustTypeSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.declarations
                    .capacity()
                    .saturating_mul(size_of::<SourceDeclaration>()),
            )
            .saturating_add(
                self.declaration_units
                    .capacity()
                    .saturating_mul(size_of::<(SourceDeclarationId, CodeUnit)>()),
            )
            .saturating_add(declaration_units)
            .saturating_add(
                self.module_names
                    .capacity()
                    .saturating_mul(size_of::<(SourceDeclarationId, String)>()),
            )
            .saturating_add(module_names)
            .saturating_add(
                self.imports
                    .capacity()
                    .saturating_mul(size_of::<SourceImportFact>()),
            )
            .saturating_add(
                self.imports
                    .iter()
                    .map(SourceImportFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
    }
}

/// How many trait-impl member pairs one workspace's enumeration may record.
///
/// Reaching the cap makes the whole enumeration non-exhaustive rather than
/// truncating it silently: every member then answers
/// [`RustMemberFamily::NotEnumerable`].
const MAX_MEMBER_PAIRS: usize = 2_000_000;

/// One member-level family edge: the member at the other end of the edge and
/// the trait or type that declares it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustMemberFamilyEdge {
    pub member: CodeUnit,
    pub owner: CodeUnit,
}

/// What this index can state about one Rust method's trait family.
///
/// Rust writes the relation down: `impl Trait for Type` names both ends, and
/// [`RustHierarchyIndex::build`] resolves both through the file's import
/// binders. The member family is that same proof read one level down -- which
/// method of the impl block answers each method the trait declares -- so an
/// edge exists only inside a resolved trait-impl edge, never where two method
/// names merely agree.
#[derive(Clone, Debug)]
pub enum RustMemberFamily {
    /// The member is not a trait method and not a member of a trait impl, so
    /// it has no trait family to state. An inherent method and a free function
    /// both land here.
    NotTracked,
    /// The member belongs to a trait whose implementations this pass could not
    /// enumerate exhaustively: a blanket impl, an impl for a type the resolver
    /// could not name, an impl whose trait reference did not resolve, or a
    /// workspace-wide failure (a file that did not parse, the pair cap).
    NotEnumerable,
    /// The complete family over the indexed workspace: the trait methods this
    /// member implements, and the members that implement it.
    Proven {
        implements: Vec<RustMemberFamilyEdge>,
        implemented_by: Vec<RustMemberFamilyEdge>,
    },
}

pub struct RustHierarchyIndex {
    pub direct_ancestors: HashMap<CodeUnit, Vec<CodeUnit>>,
    pub direct_descendants: HashMap<CodeUnit, HashSet<CodeUnit>>,
    pub relations: Vec<TypeRelation>,
    /// Trait-impl member -> the trait methods it implements.
    member_implements: HashMap<CodeUnit, Vec<RustMemberFamilyEdge>>,
    /// Trait method -> the trait-impl members that implement it. Built by
    /// indexing the same pair vector `member_implements` is built from, so the
    /// two directions cannot disagree.
    member_implemented_by: HashMap<CodeUnit, Vec<RustMemberFamilyEdge>>,
    /// Every member whose family this pass enumerated, mapped to the trait
    /// whose implementation set decides whether that enumeration is
    /// exhaustive. A trait method maps to its own trait; a trait-impl member
    /// maps to the trait its impl block names.
    member_trait: HashMap<CodeUnit, CodeUnit>,
    /// Traits whose implementation set this pass could not enumerate
    /// exhaustively. Every member on either end of such a trait answers
    /// [`RustMemberFamily::NotEnumerable`].
    unenumerable_traits: HashSet<CodeUnit>,
    /// Source alternatives whose ownership or callable shape cannot certify
    /// a method table. These are tracked failures, not non-trait methods.
    unenumerable_members: HashSet<CodeUnit>,
    /// Whether the pass saw the whole workspace. False when a file did not
    /// read or parse, or the pair cap fired, in which case no member's family
    /// can be stated as exhaustive.
    enumeration_complete: bool,
}

impl RustHierarchyIndex {
    /// One member's complete trait family, or the honest reason this index
    /// cannot state it.
    pub fn member_family(&self, member: &CodeUnit) -> RustMemberFamily {
        if self.unenumerable_members.contains(member) {
            return RustMemberFamily::NotEnumerable;
        }
        let Some(owning_trait) = self.member_trait.get(member) else {
            return RustMemberFamily::NotTracked;
        };
        if !self.enumeration_complete || self.unenumerable_traits.contains(owning_trait) {
            return RustMemberFamily::NotEnumerable;
        }
        RustMemberFamily::Proven {
            implements: self
                .member_implements
                .get(member)
                .cloned()
                .unwrap_or_default(),
            implemented_by: self
                .member_implemented_by
                .get(member)
                .cloned()
                .unwrap_or_default(),
        }
    }
}

/// One declaration's own placed coordinates: its file, that file's blob, and
/// its declaration ids there.
///
/// A `CodeUnit` can be declared more than once in a file -- the same item under
/// two `cfg`s, or two members that share a unit -- so this keeps every link
/// rather than picking one, exactly as `rust_trait_for_impl_member` does.
fn declaration_sites_of(
    rust: &dyn RustFactSource,
    unit: &CodeUnit,
) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
    let blob = rust
        .live_blobs()
        .oid_for_path(unit.source())
        .ok_or(RustCargoRouteError::Unavailable)?;
    let rel_path = rel_path_string(unit.source());
    let facts = rust.canonical_rust_hierarchy_source_facts(unit.source(), &|| true)?;
    Ok(facts
        .declaration_units
        .iter()
        .filter(|(_, candidate)| candidate == unit)
        .map(|(declaration, _)| RustPlacedDeclaration {
            rel_path: rel_path.clone(),
            blob,
            declaration: declaration.get(),
        })
        .collect())
}

/// The `CodeUnit`s that placed declarations declare.
///
/// The file a row names is the one unit's file; a blob mounted at another path
/// as well does not answer for it. The result is this call's own; nothing is
/// retained.
fn units_at_declarations(
    rust: &dyn RustFactSource,
    sites: &[RustPlacedDeclaration],
    keep_going: &dyn Fn() -> bool,
) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
    let mut units = Vec::new();
    for site in sites {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let Some(file) = live_file_at(rust, site.blob, &site.rel_path) else {
            continue;
        };
        let facts = rust.canonical_rust_hierarchy_source_facts(&file, keep_going)?;
        units.extend(
            facts
                .declaration_units
                .iter()
                .filter(|(candidate, _)| candidate.get() == site.declaration)
                .map(|(_, unit)| unit.clone()),
        );
    }
    Ok(units)
}

/// The traits one type declaration implements.
///
/// Read per demand from the trait-implementation rows crate derivation already
/// bound, seeked on the subject index. The cost is the number of impls of the
/// asked type, not the size of the workspace.
pub fn rust_direct_ancestors(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    keep_going: &dyn Fn() -> bool,
) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
    // The hierarchy is keyed by the type, not by a name for it. An alias is a
    // name, so it has no ancestors of its own: `impl Trait for WorkerAlias`
    // makes `Worker` implement the trait, and asking the alias must say
    // nothing rather than answer for the type it denotes.
    if canonical_rust_hierarchy_type(rust, token, unit.clone())?.as_ref() != Some(unit) {
        return Ok(Vec::new());
    }

    // The rows name whichever spelling the `impl` wrote, so a type reached
    // through an alias is recorded under the alias. The descendant direction
    // canonicalises its answers; this direction has to canonicalise its
    // question, which means asking under every alias that denotes this type
    // as well as under the type itself.
    let mut subjects = vec![unit.clone()];
    subjects.extend(aliases_denoting(rust, token, unit, keep_going)?);

    let mut counterparts = Vec::new();
    for subject in &subjects {
        for declaration in declaration_sites_of(rust, subject)? {
            counterparts.extend(rust.rust_traits_implemented_by(&declaration)?);
        }
    }
    let mut ancestors = units_at_declarations(rust, &counterparts, keep_going)?;
    ancestors.sort();
    ancestors.dedup();
    Ok(ancestors)
}

/// The type aliases that denote one type.
///
/// Bounded by the rows: an alias that never writes the type's name cannot
/// denote it, and a file with no alias item declares none, so only files that
/// satisfy both are read. Aliases are rare enough that this is usually empty.
fn aliases_denoting(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    keep_going: &dyn Fn() -> bool,
) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
    let live = rust.live_blobs();
    let mut denoting = Vec::new();
    for blob in rust.rust_alias_blobs_mentioning(unit.identifier())? {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        for file in live.paths_for_oid(blob) {
            let properties = rust.declaration_source_properties(&file, keep_going)?;
            for (candidate, rows) in properties.iter() {
                if candidate == unit
                    || !rows
                        .iter()
                        .any(|property| property.kind == RustDeclarationKind::TypeAlias)
                {
                    continue;
                }
                if canonical_rust_hierarchy_type(rust, token, candidate.clone())?.as_ref()
                    == Some(unit)
                {
                    denoting.push(candidate.clone());
                }
            }
        }
    }
    denoting.sort();
    denoting.dedup();
    Ok(denoting)
}

/// The implementing types a trait's rows name, each mapped to the type it
/// finally denotes.
///
/// `impl Trait for TypedModel` where `TypedModel` is an alias for
/// `Graph<TypedFact, Box<dyn TypedOp>>` names the alias in the rows, because
/// that is what the source wrote. The hierarchy answer is about the type, so
/// the alias is followed the same way the workspace pass followed it, through
/// `canonical_rust_hierarchy_type`. Without this the reader and the pass
/// disagree about `SpecialOps`, which is implemented for the alias in one
/// crate and asked about by the canonical type in another.
fn canonical_units(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    units: Vec<CodeUnit>,
) -> Result<HashSet<CodeUnit>, RustCargoRouteError> {
    let mut canonical = HashSet::default();
    for unit in units {
        if let Some(resolved) = canonical_rust_hierarchy_type(rust, token, unit)? {
            canonical.insert(resolved);
        }
    }
    Ok(canonical)
}

/// The types that implement one trait declaration. The reverse direction of
/// [`rust_direct_ancestors`], seeked on the trait index.
pub fn rust_direct_descendants(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    keep_going: &dyn Fn() -> bool,
) -> Result<HashSet<CodeUnit>, RustCargoRouteError> {
    let mut counterparts = Vec::new();
    for declaration in declaration_sites_of(rust, unit)? {
        counterparts.extend(rust.rust_types_implementing(&declaration)?);
    }
    canonical_units(
        rust,
        token,
        units_at_declarations(rust, &counterparts, keep_going)?,
    )
}

/// One Rust member's family: the trait member it answers, or the impl members
/// that answer it.
///
/// Answered per demand rather than out of a workspace map. The bound comes
/// from the question: only the member's own file, the owning trait's file and
/// the files the trait-implementation rows place an impl of that trait in can
/// contribute a pair, so those are the files read.
///
/// The one fact that bound set cannot carry is the workspace-wide one: an
/// `impl Trait for Type` whose trait reference never bound has no row in the
/// relation to be found by, and it still means the trait's implementations are
/// not exhaustively known. `rust_crate_unresolved_trait_impls` records exactly
/// those by spelling, which is why the check below is asked by identifier.
pub fn rust_member_family_of(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    member: &CodeUnit,
) -> Result<RustMemberFamily, RustCargoRouteError> {
    // A member whose own declaration properties cannot be read tells us nothing
    // about an owning trait, but that is not a failed question: the walk over
    // its own file is exactly what the workspace pass did with it, and it
    // answers. Only a genuine read failure propagates.
    let owning_trait = match owning_trait_of_member(rust, token, member) {
        Ok(found) => found,
        Err(RustCargoRouteError::Unavailable) => None,
        Err(error) => return Err(error),
    };
    if let Some(owning_trait) = owning_trait {
        let plan = TraitImplPlan::read(rust, &owning_trait)?;
        let namings = macro_namings(rust, &plan.spellings)?;
        // The member's own file first: after it, everything that decides
        // which trait the member's answer follows is known, so the walk can
        // stop as soon as that trait is known not enumerable. The trait's own
        // file next, because its item macros settle that most often.
        let mut rest: Vec<ProjectFile> = plan.files().chain(namings.keys().cloned()).collect();
        rest.push(owning_trait.source().clone());
        rest.retain(|file| file != member.source() && file != owning_trait.source());
        rest.sort();
        rest.dedup();
        let mut files = vec![member.source().clone()];
        if owning_trait.source() != member.source() {
            files.push(owning_trait.source().clone());
        }
        files.extend(rest);
        return RustHierarchyIndex::trait_member_family(
            rust,
            token,
            &owning_trait,
            member,
            &files,
            &plan,
            &namings,
        );
    }

    // No owning trait resolved. Either the member joins no trait family at all,
    // or it sits in an `impl Trait for Type` whose trait reference did not
    // resolve -- and those are opposite answers. The first is a complete
    // answer, the second is a member whose family is real but unattributable,
    // and calling it complete would let dispatch drop a target.
    //
    // A member that is in no impl at all is the overwhelmingly common case --
    // every free function, every struct, every inherent method -- and its own
    // file settles it without any walk.
    if !member_is_declared_in_an_impl(rust, member)? {
        return Ok(RustMemberFamily::NotTracked);
    }
    let files = [member.source().clone()];
    Ok(RustHierarchyIndex::read_over(rust, token, &files)?.member_family(member))
}

/// One trait's impls as its crate rows state them, grouped by the live file
/// each impl is in.
///
/// Resolving an impl header is most of what a member walk costs, and the rows
/// have already resolved every header crate derivation could bind. So an impl
/// the rows bind to the trait is taken from the row -- its trait is known and
/// its subject is the row's -- and no other impl header needs resolving
/// unless it could still name the trait: one spelled as the trait's rows spell
/// it that no row binds to the trait. Those are the impls recorded as
/// unresolved under the trait's spelling, impls whose subject has no nominal
/// path (a blanket `impl<T> Trait for T` has no row at all), and any impl whose
/// row the derivation could not bridge to its source declaration.
struct TraitImplPlan {
    /// Impl items bound to the trait, by source declaration, with the subject
    /// the row bound; `None` when the rows disagree or could not bridge it.
    bound: HashMap<ProjectFile, HashMap<u32, Option<RustPlacedDeclaration>>>,
    /// Every other file the rows place an impl of the trait, or of its
    /// spelling, in.
    other_files: HashSet<ProjectFile>,
    /// The names the trait's impl rows spelled it with.
    spellings: HashSet<String>,
}

impl TraitImplPlan {
    fn read(rust: &dyn RustFactSource, trait_unit: &CodeUnit) -> Result<Self, RustCargoRouteError> {
        let mut plan = Self {
            bound: HashMap::default(),
            other_files: HashSet::default(),
            spellings: trait_spellings(rust, trait_unit)?,
        };
        for declaration in declaration_sites_of(rust, trait_unit)? {
            for row in rust.rust_trait_impl_rows(&declaration)? {
                let Some(file) = live_file_at(rust, row.impl_blob, &row.impl_rel_path) else {
                    continue;
                };
                let Some(impl_declaration) = row.impl_declaration else {
                    plan.other_files.insert(file);
                    continue;
                };
                let subjects = plan.bound.entry(file).or_default();
                match subjects.get(&impl_declaration) {
                    None => {
                        subjects.insert(impl_declaration, row.subject);
                    }
                    Some(existing) if *existing != row.subject => {
                        subjects.insert(impl_declaration, None);
                    }
                    Some(_) => {}
                }
            }
        }
        for unresolved in rust.rust_unresolved_trait_impl_files(trait_unit.identifier())? {
            plan.other_files.extend(live_file_at(
                rust,
                unresolved.impl_blob,
                &unresolved.impl_rel_path,
            ));
        }
        Ok(plan)
    }

    fn files(&self) -> impl Iterator<Item = ProjectFile> + '_ {
        self.bound.keys().chain(self.other_files.iter()).cloned()
    }
}

/// Why one file's item macros could expand to an impl of the asked trait: the
/// file writes one of its spellings inside a macro token tree (`None`), or it
/// writes the name of a macro defined in a file that does (`Some`, with the
/// macro and its defining files).
type MacroNaming = Option<(String, Vec<ProjectFile>)>;

/// Every live file whose item macros could expand to an impl of a trait with
/// these spellings, and why. An `impl` a macro expands to is not an item until
/// the macro is replayed, and replay reads only an invocation's own tokens, so
/// no fact and no row describes one; these files are where it could come from.
/// The result lives for one question.
fn macro_namings(
    rust: &dyn RustFactSource,
    spellings: &HashSet<String>,
) -> Result<HashMap<ProjectFile, Vec<MacroNaming>>, RustCargoRouteError> {
    let mut names: Vec<String> = spellings.iter().cloned().collect();
    names.sort();
    let live = rust.live_blobs();
    let mut namings: HashMap<ProjectFile, Vec<MacroNaming>> = HashMap::default();
    for row in rust.rust_macro_expansion_blobs(&names)? {
        let naming = row
            .via
            .map(|(name, defining)| (name, live.paths_for_oid(defining)));
        for file in live.paths_for_oid(row.blob) {
            namings.entry(file).or_default().push(naming.clone());
        }
    }
    Ok(namings)
}

/// Every name an impl header can write for one trait: its own identifier and
/// the names its impl rows were spelled with, which include any rename an
/// import or re-export gave it.
fn trait_spellings(
    rust: &dyn RustFactSource,
    trait_unit: &CodeUnit,
) -> Result<HashSet<String>, RustCargoRouteError> {
    let mut spellings = HashSet::default();
    spellings.insert(trait_unit.identifier().to_string());
    for declaration in declaration_sites_of(rust, trait_unit)? {
        spellings.extend(rust.rust_trait_impl_spellings(&declaration)?);
    }
    Ok(spellings)
}

/// Whether a declaration is a direct member of some `impl` block in its own
/// file.
///
/// Read from the member's own source facts, which the reader has already
/// loaded: no resolution, no walk, no other file.
fn member_is_declared_in_an_impl(
    rust: &dyn RustFactSource,
    member: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    let facts = rust.canonical_rust_hierarchy_source_facts(member.source(), &|| true)?;
    let declarations = member_declarations(&facts, member);
    Ok(facts
        .items
        .impls
        .iter()
        .any(|impl_fact| declares_any(&impl_fact.body_children, &declarations)))
}

/// Whether a declaration is a direct member of some `trait` body in its own
/// file. The same read as [`member_is_declared_in_an_impl`], for the other
/// item that owns members.
fn member_is_declared_in_a_trait(
    rust: &dyn RustFactSource,
    member: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    let facts = rust.canonical_rust_hierarchy_source_facts(member.source(), &|| true)?;
    let declarations = member_declarations(&facts, member);
    Ok(facts
        .items
        .traits
        .iter()
        .any(|trait_fact| declares_any(&trait_fact.body_children, &declarations)))
}

/// The source declarations in its own file that link to one unit.
fn member_declarations(
    facts: &RustHierarchySourceFacts,
    member: &CodeUnit,
) -> HashSet<SourceDeclarationId> {
    facts
        .declaration_units
        .iter()
        .filter_map(|(declaration, unit)| (unit == member).then_some(*declaration))
        .collect()
}

fn declares_any(
    children: &[RustItemBodyChildSourceFact],
    declarations: &HashSet<SourceDeclarationId>,
) -> bool {
    children
        .iter()
        .filter_map(|child| child.declaration)
        .any(|child| declarations.contains(&child))
}

/// The trait one member belongs to, whether it declares the member or answers
/// it.
///
/// A trait's own method is owned by the trait whose body declares it; an impl
/// member is owned by the trait the impl names. The workspace pass recorded
/// both directions in one map, so both have to be asked here.
///
/// Which of the two applies is read from the member's own file before the
/// member's parent is consulted. An impl written outside its self type's
/// module -- `impl Source for RubyAnalyzer` in `ruby/imports.rs`, with the
/// type declared in `ruby/mod.rs` -- hangs its members from a name that has
/// no declaration in that file, so asking whether that parent is a trait has
/// no answer and used to fail the whole question. The reader then walked the
/// member's file alone, never read the trait's method table, and withheld a
/// family the workspace pass proved. Only a trait body child's parent is
/// asked, and that parent is the trait, declared in the same file.
fn owning_trait_of_member(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    member: &CodeUnit,
) -> Result<Option<CodeUnit>, RustCargoRouteError> {
    if member_is_declared_in_a_trait(rust, member)?
        && let Some(parent) = rust.parent_of(member)
        && is_rust_trait_declaration(rust, &parent)?
    {
        return Ok(Some(parent));
    }
    if let Some(trait_unit) = row_trait_of_impl_member(rust, member)? {
        return Ok(Some(trait_unit));
    }
    rust_trait_for_impl_member(rust, token, member)
}

/// The trait the crate rows say a member's impl states, when they say exactly
/// one. The member's own source facts name its impl item, and the row is
/// sought by that item; an impl the rows could not bind answers `None`, and
/// the caller resolves its header instead.
fn row_trait_of_impl_member(
    rust: &dyn RustFactSource,
    member: &CodeUnit,
) -> Result<Option<CodeUnit>, RustCargoRouteError> {
    let facts = rust.canonical_rust_hierarchy_source_facts(member.source(), &|| true)?;
    let declarations = member_declarations(&facts, member);
    let mut impls = facts
        .items
        .impls
        .iter()
        .filter(|impl_fact| declares_any(&impl_fact.body_children, &declarations));
    let (Some(impl_fact), None) = (impls.next(), impls.next()) else {
        return Ok(None);
    };
    let Some(blob) = rust.live_blobs().oid_for_path(member.source()) else {
        return Ok(None);
    };
    let impl_item = RustPlacedDeclaration {
        rel_path: rel_path_string(member.source()),
        blob,
        declaration: impl_fact.declaration.get(),
    };
    let traits = rust.rust_traits_of_impl(&impl_item)?;
    let mut units = units_at_declarations(rust, &traits, &|| true)?;
    units.sort();
    units.dedup();
    Ok(match units.as_slice() {
        [unit] => Some(unit.clone()),
        _ => None,
    })
}

pub fn rust_trait_for_impl_member(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    member: &CodeUnit,
) -> Result<Option<CodeUnit>, RustCargoRouteError> {
    let facts = rust.canonical_rust_hierarchy_source_facts(member.source(), &|| true)?;
    let contexts = RustSourceContextIndex::new(facts.as_ref(), &|| true)?;

    // The publication bridge has unique (declaration, unit) pairs. Retain
    // canonical source order, including the order of fallible resolution.
    let declaration_ids: Vec<_> = facts
        .declaration_units
        .iter()
        .filter_map(|(declaration, unit)| (unit == member).then_some(*declaration))
        .collect();
    if declaration_ids.is_empty() {
        return Err(RustCargoRouteError::Unavailable);
    }

    let mut impl_by_child = HashMap::default();
    for impl_fact in &facts.items.impls {
        for child in &impl_fact.body_children {
            let Some(declaration) = child.declaration else {
                continue;
            };
            assert!(
                impl_by_child.insert(declaration, impl_fact).is_none(),
                "one source declaration cannot be a direct child of two impl items"
            );
        }
    }

    let mut types = HashMap::default();
    for ty in &facts.types {
        assert!(
            types.insert(ty.occurrence, ty).is_none(),
            "one source occurrence cannot own two Rust type facts"
        );
    }

    let mut resolved = None;
    for declaration in declaration_ids {
        let Some(impl_fact) = impl_by_child.get(&declaration).copied() else {
            // Every source alternative must describe the same structural
            // owner. An inherent or otherwise unowned alternative therefore
            // makes the result ambiguous rather than selecting a trait one.
            return Ok(None);
        };
        let Some(trait_type) = impl_fact.trait_type else {
            return Ok(None);
        };
        let trait_type = types
            .get(&trait_type)
            .expect("published impl trait type has a type source fact");
        let binder = contexts.primary_import_binder(facts.as_ref(), impl_fact.context, &|| true)?;
        let Some(candidate) = resolve_rust_hierarchy_source_ref(
            rust,
            token,
            member.source(),
            &contexts,
            facts.as_ref(),
            impl_fact.context,
            &binder,
            trait_type,
            |candidate| is_rust_trait_declaration(rust, candidate),
        )?
        else {
            return Ok(None);
        };
        if resolved
            .as_ref()
            .is_some_and(|previous| previous != &candidate)
        {
            return Ok(None);
        }
        resolved = Some(candidate);
    }
    Ok(resolved)
}

fn units_in_package(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    resolved_package: &str,
    name: &str,
) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
    let fq_name = join_rust_fqn(resolved_package, name);
    let mut candidates: Vec<_> = rust.definitions(&fq_name).collect();
    if !candidates.is_empty() {
        candidates.sort();
        candidates.dedup();
        return Ok(candidates);
    }

    let resolved_module = resolved_package.replace('.', "::");
    let mut candidates = Vec::new();
    let module_files = resolve_module_files(rust, token, file, &resolved_module)?;
    candidates.extend(units_from_export_targets(
        rust,
        exported_targets_from_files(rust, token, &module_files, name)?.into_iter(),
    ));

    if candidates.is_empty() {
        candidates.extend(
            module_files
                .iter()
                .flat_map(|module_file| rust.declarations_named(module_file, name)),
        );
    }

    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

pub fn imported_units(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
    let targets = resolve_imported_export_from_binder(rust, token, file, binder, reference)?;
    Ok(units_from_export_targets(rust, targets.into_iter()))
}

/// Declarations a visible `use` binds, resolved against the lexical module in
/// which the impl is written. The ordinary import walk anchors relative paths
/// at the file package, which is wrong for `use super::*` inside an inline
/// module.
fn lexically_imported_units(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    lexical_package: &str,
    reference: &str,
) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
    let crate_package = rust_crate_root_package(file);
    let mut units = Vec::new();
    for (local_name, binding) in &binder.bindings {
        let imported_name = match binding.kind {
            ImportKind::Named if local_name == reference => {
                binding.imported_name.as_deref().unwrap_or(reference)
            }
            ImportKind::Glob => reference,
            ImportKind::Named
            | ImportKind::Namespace
            | ImportKind::Default
            | ImportKind::CommonJsRequire => continue,
        };
        let Some(resolved_package) = resolve_rust_module_path_with_crate(
            lexical_package,
            &crate_package,
            &binding.module_specifier,
        ) else {
            continue;
        };
        units.extend(units_in_package(
            rust,
            token,
            file,
            &resolved_package,
            imported_name,
        )?);
    }
    units.sort();
    units.dedup();
    Ok(units)
}

pub fn units_from_export_targets(
    rust: &dyn RustFactSource,
    targets: impl Iterator<Item = (ProjectFile, String)>,
) -> Vec<CodeUnit> {
    let mut units: Vec<_> = targets
        .flat_map(|(file, name)| rust.declarations_named(&file, &name))
        .collect();
    units.sort();
    units.dedup();
    units
}
/// Record why one trait left the member family's proven set.
///
/// Set `BIFROST_DEBUG_RUST_FAMILY=1` to print one line per disqualification,
/// which is how the enumeration's real cost was measured at corpus scale --
/// the same route `BIFROST_DEBUG_CHA` gives the dispatch consumer. The rules
/// are all conservative, so this is the only way to tell an honest "no
/// implementor exists" apart from "the resolver could not name this trait".
fn note_disqualified(rule: &str, detail: &str) {
    if std::env::var_os("BIFROST_DEBUG_RUST_FAMILY").is_some() {
        eprintln!("rust_family_disqualified rule={rule} {detail}");
    }
}

/// One method a trait declares, as the member enumeration reads it.
struct TraitMethod {
    name: String,
    /// Parameter count including the `self` receiver, read from the
    /// declaration's `parameters` node rather than from rendered text.
    arity: Option<usize>,
    unit: CodeUnit,
}

/// One member of a resolved trait impl, held until every trait's own method
/// table is known.
///
/// The trait may be declared in a file this pass has not reached yet, and
/// holding tree-sitter nodes across files would mean keeping every parsed tree
/// alive, so the pair is completed after the walk from owned data.
struct PendingImplMember {
    owning_trait: CodeUnit,
    implementer: CodeUnit,
    member: CodeUnit,
    name: String,
    arity: Option<usize>,
}

/// Borrowed per-file indexes shared by trait-table and primary-impl
/// enumeration. The declaration bridge is intentionally indexed only in the
/// source-declaration direction plus a multiplicity count: no consumer needs
/// a second reverse source-ID vector, and all ownership decisions remain
/// exact source-ID lookups.
struct RustHierarchyFileIndex<'facts> {
    facts: &'facts RustHierarchySourceFacts,
    contexts: RustSourceContextIndex,
    declarations: HashMap<SourceDeclarationId, Vec<&'facts CodeUnit>>,
    source_count_by_unit: HashMap<&'facts CodeUnit, usize>,
    callables: HashMap<SourceDeclarationId, &'facts RustCallableSourceFact>,
    syntax: HashMap<SourceOccurrenceId, bool>,
    types: HashMap<SourceOccurrenceId, &'facts RustTypeSourceFact>,
    generics: HashMap<SourceDeclarationId, &'facts [RustGenericParameterSourceFact]>,
    impls_by_tree_root: HashMap<SourceOccurrenceId, Vec<&'facts RustImplSourceFact>>,
}

impl<'facts> RustHierarchyFileIndex<'facts> {
    fn new(
        facts: &'facts RustHierarchySourceFacts,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Self, RustCargoRouteError> {
        let mut declarations = HashMap::default();
        let mut source_count_by_unit = HashMap::default();
        for (declaration, unit) in &facts.declaration_units {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            declarations
                .entry(*declaration)
                .or_insert_with(Vec::new)
                .push(unit);
            *source_count_by_unit.entry(unit).or_default() += 1;
        }

        let mut callables = HashMap::default();
        for callable in &facts.items.callables {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                callables.insert(callable.declaration, callable).is_none(),
                "one callable declaration has one canonical source fact"
            );
        }

        let mut syntax = HashMap::default();
        for row in &facts.items.syntax {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                syntax.insert(row.occurrence, row.has_error).is_none(),
                "one source occurrence cannot own two syntax facts"
            );
        }
        let mut types = HashMap::default();
        for ty in &facts.types {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                types.insert(ty.occurrence, ty).is_none(),
                "one source occurrence cannot own two Rust type facts"
            );
        }
        let mut generics = HashMap::default();
        for generic in &facts.items.generics {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                !generic.parameters.is_empty(),
                "published generic groups contain at least one parameter"
            );
            assert!(
                generics
                    .insert(generic.declaration, generic.parameters.as_slice())
                    .is_none(),
                "one source declaration cannot own two generic groups"
            );
        }
        let contexts = RustSourceContextIndex::new(facts, keep_going)?;
        let mut impls_by_tree_root = HashMap::default();
        for impl_fact in &facts.items.impls {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let root = contexts.nearest_tree_root(impl_fact.context)?;
            impls_by_tree_root
                .entry(root)
                .or_insert_with(Vec::new)
                .push(impl_fact);
        }

        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }

        Ok(Self {
            facts,
            contexts,
            declarations,
            source_count_by_unit,
            callables,
            syntax,
            types,
            generics,
            impls_by_tree_root,
        })
    }
}

/// What one trait declaration's own file says about the members it declares.
enum TraitMethodTable {
    /// The trait declaration itself could not be named unambiguously: it links
    /// to no unit, to several, or to a unit the file declares more than once.
    /// Nothing about it can be enumerated, including its members.
    Unnameable {
        traits: Vec<CodeUnit>,
        members: Vec<CodeUnit>,
    },
    /// The trait was named. `complete` is false when the file did not give a
    /// whole picture of the declaration -- unparsed syntax, a missing body, or
    /// a macro invocation in the body that can contribute members -- in which
    /// case the table is a lower bound and no family across it is proven.
    Read {
        unit: CodeUnit,
        methods: Vec<TraitMethod>,
        complete: bool,
        unnameable_members: Vec<CodeUnit>,
    },
}

/// One trait's declared member table, read from the trait's own file.
///
/// This is the whole of what the workspace pass used to record per trait, and
/// it never needed more than the one file: a trait declares its members inline.
/// Lifting it out of the pass is what lets a per-demand reader answer the same
/// question for one trait without walking the workspace to build a map of all
/// of them.
fn read_trait_method_table(
    source_index: &RustHierarchyFileIndex<'_>,
    trait_fact: &RustTraitSourceFact,
) -> TraitMethodTable {
    let facts = source_index.facts;
    let declarations = &source_index.declarations;
    let source_count_by_unit = &source_index.source_count_by_unit;
    let callables = &source_index.callables;
    let syntax = &source_index.syntax;

    let trait_links = declarations
        .get(&trait_fact.declaration)
        .map_or(&[][..], Vec::as_slice);
    let trait_units = trait_links
        .iter()
        .copied()
        .filter(|unit| unit.is_class())
        .collect::<Vec<_>>();
    let trait_is_ambiguous = trait_units.len() != 1
        || trait_units.len() != trait_links.len()
        || trait_units
            .iter()
            .any(|unit| source_count_by_unit[unit] != 1);
    if trait_is_ambiguous {
        let mut members = Vec::new();
        for child in &trait_fact.body_children {
            if matches!(
                child.syntax_kind.as_str(),
                "function_item" | "function_signature_item"
            ) && let Some(links) = child.declaration.and_then(|id| declarations.get(&id))
            {
                members.extend(
                    links
                        .iter()
                        .copied()
                        .filter(|unit| unit.is_function())
                        .cloned(),
                );
            }
        }
        return TraitMethodTable::Unnameable {
            traits: trait_units.into_iter().cloned().collect(),
            members,
        };
    }

    let trait_unit = trait_units[0];
    let mut methods = Vec::new();
    let mut unnameable_members = Vec::new();
    let mut complete = true;
    let trait_declaration = &facts.declarations[trait_fact.declaration.index()];
    if syntax.get(&trait_declaration.occurrence).copied() != Some(false) {
        complete = false;
    }
    if let Some(body) = trait_fact.body {
        if syntax.get(&body).copied() != Some(false) {
            complete = false;
        }
    } else {
        complete = false;
    }

    for child in &trait_fact.body_children {
        if syntax.get(&child.occurrence).copied() != Some(false) {
            complete = false;
        }
        match child.syntax_kind.as_str() {
            "function_item" | "function_signature_item" => {
                let Some(declaration) = child.declaration else {
                    complete = false;
                    continue;
                };
                let Some(method_links) = declarations.get(&declaration) else {
                    complete = false;
                    continue;
                };
                let method_units = method_links
                    .iter()
                    .copied()
                    .filter(|unit| unit.is_function())
                    .collect::<Vec<_>>();
                let method_is_ambiguous = method_units.len() != 1
                    || method_units.len() != method_links.len()
                    || method_units
                        .iter()
                        .any(|unit| source_count_by_unit[unit] != 1);
                if method_is_ambiguous {
                    complete = false;
                    unnameable_members.extend(method_units.into_iter().cloned());
                    continue;
                }
                let unit = method_units[0];
                let Some(callable) = callables.get(&declaration) else {
                    unnameable_members.push(unit.clone());
                    complete = false;
                    continue;
                };
                if callable.parameters.is_none() {
                    complete = false;
                }
                let arity = callable
                    .parameter_children
                    .iter()
                    .filter(|parameter| parameter.syntax_kind != "attribute_item")
                    .count();
                methods.push(TraitMethod {
                    name: unit.identifier().to_string(),
                    arity: Some(arity),
                    unit: unit.clone(),
                });
            }
            "associated_type" | "type_item" => {
                let links = child.declaration.and_then(|id| declarations.get(&id));
                let Some([unit]) = links.map(Vec::as_slice) else {
                    complete = false;
                    continue;
                };
                if !unit.is_class() || source_count_by_unit[unit] != 1 {
                    complete = false;
                    continue;
                }
                methods.push(TraitMethod {
                    name: unit.identifier().to_string(),
                    arity: None,
                    unit: (*unit).clone(),
                });
            }
            "macro_invocation" => {
                note_disqualified(
                    "macro_in_trait_body",
                    &format!("trait={}", trait_unit.fq_name()),
                );
                complete = false;
            }
            _ => {}
        }
    }

    TraitMethodTable::Read {
        unit: trait_unit.clone(),
        methods,
        complete,
        unnameable_members,
    }
}

/// Where an impl's implementer comes from once its trait is known: its own
/// header, resolved through the impl's visible binder, or the subject the
/// crate row already bound.
enum ImplSubject<'a> {
    Resolve(&'a ImportBinder),
    Row(&'a RustPlacedDeclaration),
}

/// The accumulating state of one workspace's hierarchy and member-family walk.
#[derive(Default)]
struct RustHierarchyBuilder {
    direct_ancestors: HashMap<CodeUnit, Vec<CodeUnit>>,
    direct_descendants: HashMap<CodeUnit, HashSet<CodeUnit>>,
    relations: Vec<TypeRelation>,
    trait_methods: HashMap<CodeUnit, Vec<TraitMethod>>,
    member_trait: HashMap<CodeUnit, CodeUnit>,
    pending: Vec<PendingImplMember>,
    unenumerable_traits: HashSet<CodeUnit>,
    unenumerable_members: HashSet<CodeUnit>,
    /// The terminal identifier of every impl trait reference this pass could
    /// not resolve to a workspace trait. A trait of that name is not
    /// exhaustively enumerated, because one of the impls naming it was never
    /// attributed to any trait.
    unresolved_trait_identifiers: HashSet<String>,
    enumeration_complete: bool,
}

impl RustHierarchyIndex {
    /// The hierarchy and member-family facts carried by one bounded set of
    /// files.
    ///
    /// This used to read `get_analyzed_files()` and was memoized for the life
    /// of the analyzer, which made one changed file cost a rebuild over every
    /// declaration in the workspace. The rules it applies are per file and per
    /// trait, so the same code answers one question when it is given only the
    /// files that question can reach: the member's own file, the owning trait's
    /// file, and the files the trait-implementation rows say hold an impl of
    /// that trait. The result belongs to the call that asked; nothing here is
    /// retained.
    pub fn read_over(
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        files: &[ProjectFile],
    ) -> Result<Self, RustCargoRouteError> {
        let mut builder = RustHierarchyBuilder {
            enumeration_complete: true,
            ..RustHierarchyBuilder::default()
        };

        for file in files {
            let source_facts = rust.canonical_rust_hierarchy_source_facts(file, &|| true)?;
            let source_index = RustHierarchyFileIndex::new(source_facts.as_ref(), &|| true)?;
            builder.record_trait_methods(&source_index)?;
            for macro_fact in &source_index.facts.items.macros {
                builder.record_macro_expansion(rust, token, file, &source_index, macro_fact)?;
            }
            for impl_fact in &source_index.facts.items.impls {
                if !source_index
                    .contexts
                    .is_primary(source_index.facts, impl_fact.context)?
                {
                    continue;
                }
                builder.record_primary_impl(rust, token, file, &source_index, impl_fact)?;
            }
        }

        Ok(builder.finish())
    }

    /// The member-family facts of one trait over its bounded file set, with the
    /// trait's impls taken from its crate rows (see [`TraitImplPlan`]).
    ///
    /// Every other fact of each file is read as [`Self::read_over`] reads it:
    /// trait tables, macro trees, and the pairing rules. An impl header the plan
    /// does not bind is resolved only when it could still name the trait: it
    /// has no nominal name to compare, it is spelled as the trait's rows spell
    /// it, or it is the impl that declares `member`, which is where the
    /// member's own impl is classified.
    ///
    /// A file in the set may also hold an item macro whose expansion replay
    /// does not see; see [`RustHierarchyBuilder::account_item_macros`].
    ///
    /// `files` starts with `member`'s own file. The walk stops as soon as the
    /// facts read so far already make `member`'s answer NotEnumerable (see
    /// [`RustHierarchyBuilder::settles_not_enumerable`]); the rest of the
    /// files could not change it.
    fn trait_member_family(
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        trait_unit: &CodeUnit,
        member: &CodeUnit,
        files: &[ProjectFile],
        plan: &TraitImplPlan,
        namings: &HashMap<ProjectFile, Vec<MacroNaming>>,
    ) -> Result<RustMemberFamily, RustCargoRouteError> {
        assert_eq!(
            files.first(),
            Some(member.source()),
            "the member's own file is read first"
        );
        let mut builder = RustHierarchyBuilder {
            enumeration_complete: true,
            ..RustHierarchyBuilder::default()
        };
        let mut deciding_traits = Vec::new();

        for (position, file) in files.iter().enumerate() {
            let source_facts = rust.canonical_rust_hierarchy_source_facts(file, &|| true)?;
            let source_index = RustHierarchyFileIndex::new(source_facts.as_ref(), &|| true)?;
            builder.record_trait_methods(&source_index)?;
            for macro_fact in &source_index.facts.items.macros {
                builder.record_macro_expansion(rust, token, file, &source_index, macro_fact)?;
            }
            if let Some(namings) = namings.get(file) {
                builder.account_item_macros(
                    rust,
                    token,
                    file,
                    &source_index,
                    trait_unit,
                    &plan.spellings,
                    namings,
                )?;
            }
            let bound = plan.bound.get(file);
            let member_declarations =
                (file == member.source()).then(|| member_declarations(source_index.facts, member));
            for impl_fact in &source_index.facts.items.impls {
                if !source_index
                    .contexts
                    .is_primary(source_index.facts, impl_fact.context)?
                {
                    continue;
                }
                let Some(trait_occurrence) = impl_fact.trait_type else {
                    continue;
                };
                let declaration = impl_fact.declaration.get();
                if let Some(subject) = bound.and_then(|bound| bound.get(&declaration)) {
                    let binder;
                    let subject = match subject {
                        Some(subject) => ImplSubject::Row(subject),
                        None => {
                            binder = source_index.contexts.visible_import_binder(
                                source_index.facts,
                                impl_fact.context,
                                &|| true,
                            )?;
                            ImplSubject::Resolve(&binder)
                        }
                    };
                    builder.record_impl_of(
                        rust,
                        token,
                        file,
                        &source_index,
                        impl_fact,
                        trait_unit,
                        subject,
                    )?;
                    continue;
                }
                let resolves = match source_type_identifier(source_index.types[&trait_occurrence]) {
                    None => true,
                    Some(name) => {
                        plan.spellings.contains(name)
                            || member_declarations.as_ref().is_some_and(|declarations| {
                                declares_any(&impl_fact.body_children, declarations)
                            })
                    }
                };
                if resolves {
                    builder.record_primary_impl(rust, token, file, &source_index, impl_fact)?;
                }
            }
            if position == 0 {
                deciding_traits = builder.deciding_traits(member);
            }
            if builder.settles_not_enumerable(member, &deciding_traits) {
                note_disqualified(
                    "walk_stopped",
                    &format!(
                        "member={} files_read={} files={}",
                        member.fq_name(),
                        position + 1,
                        files.len()
                    ),
                );
                return Ok(RustMemberFamily::NotEnumerable);
            }
        }

        Ok(builder.finish().member_family(member))
    }
}

impl RustHierarchyBuilder {
    /// The traits whose enumerability `member`'s answer follows, once the
    /// member's own file has been read: the trait whose method table lists it,
    /// or the traits its impls were recorded against. No other file declares
    /// the member, so no later file adds to these.
    fn deciding_traits(&self, member: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(owning_trait) = self.member_trait.get(member) {
            return vec![owning_trait.clone()];
        }
        self.pending
            .iter()
            .filter(|pending| &pending.member == member)
            .map(|pending| pending.owning_trait.clone())
            .collect()
    }

    /// Whether the facts recorded so far already make `member`'s answer
    /// [`RustMemberFamily::NotEnumerable`], whatever the rest of the walk
    /// reads.
    ///
    /// Every set this consults only grows and `enumeration_complete` only
    /// falls, so the answer [`RustHierarchyIndex::member_family`] gives after
    /// [`Self::finish`] is the same: an unenumerable member stays one, and a
    /// member whose deciding traits are all unenumerable answers
    /// NotEnumerable whether `finish` pairs it (the member then follows its
    /// trait) or not (the member itself becomes unenumerable).
    fn settles_not_enumerable(&self, member: &CodeUnit, deciding_traits: &[CodeUnit]) -> bool {
        self.unenumerable_members.contains(member)
            || (!deciding_traits.is_empty()
                && (!self.enumeration_complete
                    || deciding_traits
                        .iter()
                        .all(|owning_trait| self.unenumerable_traits.contains(owning_trait))))
    }

    /// Record the methods one canonical primary-tree trait declares, so that
    /// the pairing pass can join an impl member to the exact declaration it
    /// answers. Embedded traits are retained as source evidence but are not
    /// promoted into this hierarchy index.
    fn record_trait_methods(
        &mut self,
        source_index: &RustHierarchyFileIndex<'_>,
    ) -> Result<(), RustCargoRouteError> {
        let facts = source_index.facts;
        let contexts = &source_index.contexts;

        for trait_fact in &facts.items.traits {
            if !contexts.is_primary(facts, trait_fact.context)? {
                continue;
            }
            match read_trait_method_table(source_index, trait_fact) {
                TraitMethodTable::Unnameable { traits, members } => {
                    self.unenumerable_traits.extend(traits);
                    self.unenumerable_members.extend(members);
                }
                TraitMethodTable::Read {
                    unit,
                    methods,
                    complete,
                    unnameable_members,
                } => {
                    self.unenumerable_members.extend(unnameable_members);
                    if !complete {
                        self.unenumerable_traits.insert(unit.clone());
                    }
                    for method in &methods {
                        self.member_trait.insert(method.unit.clone(), unit.clone());
                    }
                    self.trait_methods.entry(unit).or_default().extend(methods);
                }
            }
        }
        Ok(())
    }

    fn record_primary_impl(
        &mut self,
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source_index: &RustHierarchyFileIndex<'_>,
        impl_fact: &RustImplSourceFact,
    ) -> Result<(), RustCargoRouteError> {
        let Some(trait_occurrence) = impl_fact.trait_type else {
            return Ok(());
        };
        let trait_type = source_index
            .types
            .get(&trait_occurrence)
            .copied()
            .expect("published impl trait type has a type source fact");
        let binder = source_index.contexts.visible_import_binder(
            source_index.facts,
            impl_fact.context,
            &|| true,
        )?;
        let Some(trait_unit) = resolve_rust_hierarchy_source_ref(
            rust,
            token,
            file,
            &source_index.contexts,
            source_index.facts,
            impl_fact.context,
            &binder,
            trait_type,
            |candidate| is_rust_trait_declaration(rust, candidate),
        )?
        else {
            if let Some(identifier) = source_type_identifier(trait_type) {
                note_disqualified(
                    "unresolved_trait_ref",
                    &format!("ident={identifier} file={file:?}"),
                );
                self.unresolved_trait_identifiers
                    .insert(identifier.to_string());
            } else {
                self.enumeration_complete = false;
            }
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return Ok(());
        };
        self.record_impl_of(
            rust,
            token,
            file,
            source_index,
            impl_fact,
            &trait_unit,
            ImplSubject::Resolve(&binder),
        )
    }

    /// Record one impl already known to state `trait_unit`: its checks, its
    /// implementer, and its members. The implementer comes from the crate row
    /// when the caller has one, and is resolved from the header otherwise.
    #[allow(clippy::too_many_arguments)]
    fn record_impl_of(
        &mut self,
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source_index: &RustHierarchyFileIndex<'_>,
        impl_fact: &RustImplSourceFact,
        trait_unit: &CodeUnit,
        subject: ImplSubject<'_>,
    ) -> Result<(), RustCargoRouteError> {
        let trait_unit = trait_unit.clone();
        if impl_fact.negation.is_some() {
            note_disqualified(
                "negative_impl",
                &format!("trait={} file={file:?}", trait_unit.fq_name()),
            );
            self.unenumerable_traits.insert(trait_unit);
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return Ok(());
        }

        let Some(target_occurrence) = impl_fact.target_type else {
            note_disqualified(
                "missing_impl_target",
                &format!("trait={} file={file:?}", trait_unit.fq_name()),
            );
            self.unenumerable_traits.insert(trait_unit);
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return Ok(());
        };
        let target_type = source_index
            .types
            .get(&target_occurrence)
            .copied()
            .expect("published impl target type has a type source fact");
        let generic_parameters = source_index
            .generics
            .get(&impl_fact.declaration)
            .copied()
            .unwrap_or(&[]);
        if generic_impl_target_is_dependent(generic_parameters, target_type) {
            note_disqualified(
                "generic_impl_target",
                &format!("trait={}", trait_unit.fq_name()),
            );
            self.unenumerable_traits.insert(trait_unit);
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return Ok(());
        }

        let named = match subject {
            ImplSubject::Resolve(binder) => resolve_rust_hierarchy_source_ref(
                rust,
                token,
                file,
                &source_index.contexts,
                source_index.facts,
                impl_fact.context,
                binder,
                target_type,
                |candidate| {
                    Ok(is_rust_struct_declaration(rust, candidate)?
                        || is_rust_enum_declaration(rust, candidate)?
                        || is_rust_type_alias_declaration(rust, candidate)?)
                },
            )?,
            ImplSubject::Row(declaration) => {
                let mut units =
                    units_at_declarations(rust, std::slice::from_ref(declaration), &|| true)?;
                units.sort();
                units.dedup();
                match units.as_slice() {
                    [unit] => Some(unit.clone()),
                    _ => None,
                }
            }
        };
        let Some(implementer) = named else {
            note_disqualified(
                "unresolved_impl_type",
                &format!("trait={} file={file:?}", trait_unit.fq_name()),
            );
            self.unenumerable_traits.insert(trait_unit);
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return Ok(());
        };
        let Some(implementer) = canonical_rust_hierarchy_type(rust, token, implementer)? else {
            note_disqualified(
                "unresolved_impl_type",
                &format!("trait={} file={file:?}", trait_unit.fq_name()),
            );
            self.unenumerable_traits.insert(trait_unit);
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return Ok(());
        };

        let ancestors = self
            .direct_ancestors
            .entry(implementer.clone())
            .or_default();
        if !ancestors.contains(&trait_unit) {
            ancestors.push(trait_unit.clone());
        }
        self.direct_descendants
            .entry(trait_unit.clone())
            .or_default()
            .insert(implementer.clone());
        self.relations.push(TypeRelation {
            from: implementer.clone(),
            to: trait_unit.clone(),
            kind: TypeRelationKind::TraitImplementation,
        });

        self.record_primary_impl_members(source_index, impl_fact, &trait_unit, &implementer);
        Ok(())
    }

    fn record_primary_impl_members(
        &mut self,
        source_index: &RustHierarchyFileIndex<'_>,
        impl_fact: &RustImplSourceFact,
        trait_unit: &CodeUnit,
        implementer: &CodeUnit,
    ) {
        let Some(body) = impl_fact.body else {
            self.unenumerable_traits.insert(trait_unit.clone());
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return;
        };
        let impl_declaration = source_index
            .facts
            .declarations
            .get(impl_fact.declaration.index())
            .expect("published impl declaration has a source fact");
        if source_index
            .syntax
            .get(&impl_declaration.occurrence)
            .copied()
            != Some(false)
            || source_index.syntax.get(&body).copied() != Some(false)
        {
            self.unenumerable_traits.insert(trait_unit.clone());
            self.mark_source_impl_members_unenumerable(source_index, impl_fact);
            return;
        }

        for child in &impl_fact.body_children {
            match child.syntax_kind.as_str() {
                "function_item" => {
                    let Some(declaration) = child.declaration else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    let Some(links) = source_index.declarations.get(&declaration) else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    let [member] = links.as_slice() else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        self.mark_source_impl_child_members_unenumerable(source_index, child);
                        continue;
                    };
                    let member = *member;
                    if !member.is_function() || source_index.source_count_by_unit[member] != 1 {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        self.mark_source_impl_child_members_unenumerable(source_index, child);
                        continue;
                    }
                    if source_index.syntax.get(&child.occurrence).copied() != Some(false) {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        self.unenumerable_members.insert(member.clone());
                        continue;
                    }
                    let Some(callable) = source_index.callables.get(&declaration).copied() else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        self.unenumerable_members.insert(member.clone());
                        continue;
                    };
                    if callable.parameters.is_none() {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        self.unenumerable_members.insert(member.clone());
                        continue;
                    }
                    if self.pending.len() >= MAX_MEMBER_PAIRS {
                        self.enumeration_complete = false;
                        return;
                    }
                    let arity = callable
                        .parameter_children
                        .iter()
                        .filter(|parameter| parameter.syntax_kind != "attribute_item")
                        .count();
                    self.pending.push(PendingImplMember {
                        owning_trait: trait_unit.clone(),
                        implementer: implementer.clone(),
                        member: member.clone(),
                        name: member.identifier().to_string(),
                        arity: Some(arity),
                    });
                }
                "type_item" => {
                    let links = child
                        .declaration
                        .and_then(|id| source_index.declarations.get(&id));
                    let Some([member]) = links.map(Vec::as_slice) else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    if !member.is_class()
                        || source_index.source_count_by_unit[member] != 1
                        || source_index.syntax.get(&child.occurrence).copied() != Some(false)
                    {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    }
                    if self.pending.len() >= MAX_MEMBER_PAIRS {
                        self.enumeration_complete = false;
                        return;
                    }
                    self.pending.push(PendingImplMember {
                        owning_trait: trait_unit.clone(),
                        implementer: implementer.clone(),
                        member: (*member).clone(),
                        name: member.identifier().to_string(),
                        arity: None,
                    });
                }
                "macro_invocation" => {
                    note_disqualified(
                        "macro_in_impl_body",
                        &format!("trait={}", trait_unit.fq_name()),
                    );
                    self.unenumerable_traits.insert(trait_unit.clone());
                }
                _ => {}
            }
        }
    }

    fn mark_source_impl_members_unenumerable(
        &mut self,
        source_index: &RustHierarchyFileIndex<'_>,
        impl_fact: &RustImplSourceFact,
    ) {
        for child in &impl_fact.body_children {
            if child.syntax_kind != "function_item" {
                continue;
            }
            self.mark_source_impl_child_members_unenumerable(source_index, child);
        }
    }

    fn mark_source_impl_child_members_unenumerable(
        &mut self,
        source_index: &RustHierarchyFileIndex<'_>,
        child: &RustItemBodyChildSourceFact,
    ) {
        let Some(declaration) = child.declaration else {
            return;
        };
        if let Some(links) = source_index.declarations.get(&declaration) {
            self.unenumerable_members.extend(
                links
                    .iter()
                    .filter(|unit| unit.is_function())
                    .copied()
                    .cloned(),
            );
        }
    }

    /// Account for the trait impls that live inside a macro's token tree.
    ///
    /// The declaration walk records items from a parsed direct-item macro
    /// tree, so such an impl *is* part of the indexed workspace even though it
    /// is not an `impl_item` of the file's own parse. This pass does not
    /// enumerate those members; it marks the traits they name so no family
    /// claims to be exhaustive over an impl it cannot read.
    fn record_macro_expansion(
        &mut self,
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source_index: &RustHierarchyFileIndex<'_>,
        macro_fact: &RustItemMacroSourceFact,
    ) -> Result<(), RustCargoRouteError> {
        if macro_fact.position != RustItemMacroSourcePosition::DirectItem
            || !source_index
                .contexts
                .is_primary(source_index.facts, macro_fact.context)?
        {
            return Ok(());
        }

        let root = match macro_fact.expansion {
            RustItemMacroExpansion::Parsed(root) => root,
            RustItemMacroExpansion::EmptyInterior => return Ok(()),
            RustItemMacroExpansion::Unavailable(_) | RustItemMacroExpansion::NotRequested => {
                // A direct item macro whose replay was unavailable cannot
                // support an exhaustive hierarchy result. It is not an
                // empty expansion, so retain uncertainty rather than making
                // a false negative look like a proof.
                self.enumeration_complete = false;
                return Ok(());
            }
        };
        self.record_replayed_impls(rust, token, file, source_index, root)
    }

    /// Account for the item macros of one file that could expand to an impl
    /// of the one trait a bounded walk asks about, on the trait's behalf.
    ///
    /// The file is one [`macro_namings`] found: it writes one of the trait's
    /// spellings inside a macro token tree, or the name of a macro defined in a
    /// file that does. Replay reads only an invocation's own tokens, so what a
    /// macro's rules add to them is seen by no fact and no row, as with
    /// tract's `element_wise!(..);`, whose rules write the impl. An invocation
    /// could name the trait when its own input writes a spelling, or when it
    /// invokes one of the macros that brought the file here; a qualified
    /// invocation's macro has no recorded name, so it could be any of them.
    /// Only an invocation crate derivation decided to be a passthrough (its
    /// rules replay the arguments' items and add nothing but a `cfg`
    /// decoration) is known not to add one; any other such module-level item
    /// invocation makes the trait's implementations not exhaustively known,
    /// and is the reason. A decided statement-position invocation's arguments
    /// are read the way a direct item's are: an impl among them is
    /// uncertainty, never a promoted edge, unless the decoration is inactive
    /// in every crate that places the file, when none of them is compiled.
    /// An invocation in a
    /// trait or impl body cannot declare an impl, and one in a function body
    /// is not at an item position.
    #[allow(clippy::too_many_arguments)]
    fn account_item_macros(
        &mut self,
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source_index: &RustHierarchyFileIndex<'_>,
        trait_unit: &CodeUnit,
        spellings: &HashSet<String>,
        namings: &[MacroNaming],
    ) -> Result<(), RustCargoRouteError> {
        if self.unenumerable_traits.contains(trait_unit) {
            return Ok(());
        }
        let facts = source_index.facts;
        let mut invocations = Vec::new();
        for macro_fact in &facts.items.macros {
            if macro_fact.position == RustItemMacroSourcePosition::Other
                || !source_index
                    .contexts
                    .is_primary(facts, macro_fact.context)?
            {
                continue;
            }
            let context = source_index.contexts.context(facts, macro_fact.context)?;
            if matches!(
                context.kind,
                RustSourceContextKind::FileRoot | RustSourceContextKind::Module
            ) {
                invocations.push(macro_fact);
            }
        }
        if invocations.is_empty() {
            return Ok(());
        }
        let invoked: HashSet<&str> = namings
            .iter()
            .flatten()
            .map(|(name, _)| name.as_str())
            .collect();
        let inputs: HashMap<SourceOccurrenceId, &RustMacroTokenTree> = facts
            .items
            .macro_inputs
            .iter()
            .map(|input| (input.invocation, &input.tree))
            .collect();
        let decisions = rust.rust_item_macro_decisions(file)?;
        for macro_fact in invocations {
            let decision = decisions
                .iter()
                .find(|decision| decision.invocation == macro_fact.invocation)
                .unwrap_or_else(|| {
                    panic!(
                        "an item-position macro invocation has its stored row: {macro_fact:?} \
                         in {file:?}, rows {decisions:?}"
                    )
                });
            let input = inputs.get(&macro_fact.invocation).unwrap_or_else(|| {
                panic!(
                    "an item-position macro invocation has its input: {macro_fact:?} in {file:?}"
                )
            });
            let input_names_trait = input.tokens.iter().any(|token| {
                token.syntax_kind == "identifier" && spellings.contains(input.token_text(token))
            });
            let invokes_naming_macro = match decision.name.as_deref() {
                Some(name) => invoked.contains(name),
                None => !invoked.is_empty(),
            };
            if !input_names_trait && !invokes_naming_macro {
                continue;
            }
            match decision.decided {
                // Its items exist in no crate that places the file.
                RustItemMacroDecided::Passthrough { compiled: false } => continue,
                RustItemMacroDecided::Passthrough { compiled: true } => {
                    match (macro_fact.position, macro_fact.expansion) {
                        // `record_macro_expansion` replayed it already.
                        (RustItemMacroSourcePosition::DirectItem, _) => continue,
                        (_, RustItemMacroExpansion::Parsed(root)) => {
                            self.record_replayed_impls(rust, token, file, source_index, root)?;
                            continue;
                        }
                        (_, RustItemMacroExpansion::EmptyInterior) => continue,
                        _ => {}
                    }
                }
                RustItemMacroDecided::Undecided => {}
            }
            note_disqualified(
                "unexpanded_item_macro",
                &format!(
                    "trait={} macro={:?} position={:?} invocation={:?} file={file:?} \
                     input_names_trait={input_names_trait} namings={namings:?}",
                    trait_unit.fq_name(),
                    decision.name,
                    macro_fact.position,
                    macro_fact.invocation
                ),
            );
            self.unenumerable_traits.insert(trait_unit.clone());
            return Ok(());
        }
        Ok(())
    }

    /// Record the impls one replayed macro interior holds: each makes the
    /// trait it names unenumerable, and none is promoted to an edge.
    fn record_replayed_impls(
        &mut self,
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source_index: &RustHierarchyFileIndex<'_>,
        root: SourceOccurrenceId,
    ) -> Result<(), RustCargoRouteError> {
        for impl_fact in source_index
            .impls_by_tree_root
            .get(&root)
            .into_iter()
            .flatten()
        {
            let Some(trait_occurrence) = impl_fact.trait_type else {
                continue;
            };
            let trait_ref = source_index
                .types
                .get(&trait_occurrence)
                .copied()
                .expect("published macro impl trait type has a type source fact");
            let binder = source_index.contexts.primary_import_binder(
                source_index.facts,
                impl_fact.context,
                &|| true,
            )?;
            match resolve_rust_hierarchy_source_ref(
                rust,
                token,
                file,
                &source_index.contexts,
                source_index.facts,
                impl_fact.context,
                &binder,
                trait_ref,
                |candidate| is_rust_trait_declaration(rust, candidate),
            ) {
                Ok(Some(trait_unit)) => {
                    note_disqualified(
                        "macro_item_impl",
                        &format!("trait={}", trait_unit.fq_name()),
                    );
                    self.unenumerable_traits.insert(trait_unit);
                }
                Ok(None) => {
                    if let Some(identifier) = source_type_identifier(trait_ref) {
                        self.unresolved_trait_identifiers
                            .insert(identifier.to_string());
                    } else {
                        self.enumeration_complete = false;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Join every pending impl member to the trait method it answers, then
    /// index the resulting pairs in both directions from the one vector.
    fn finish(mut self) -> RustHierarchyIndex {
        let named_unresolved: Vec<CodeUnit> = self
            .trait_methods
            .keys()
            .filter(|trait_unit| {
                self.unresolved_trait_identifiers
                    .contains(trait_unit.identifier())
            })
            .cloned()
            .collect();
        self.unenumerable_traits.extend(named_unresolved);

        let mut member_implements: HashMap<CodeUnit, Vec<RustMemberFamilyEdge>> =
            HashMap::default();
        let mut member_implemented_by: HashMap<CodeUnit, Vec<RustMemberFamilyEdge>> =
            HashMap::default();
        for pending in std::mem::take(&mut self.pending) {
            let Some(methods) = self.trait_methods.get(&pending.owning_trait) else {
                // The impl resolved to a trait whose own declaration this pass
                // never read, so there is nothing to match its members against.
                note_disqualified(
                    "trait_never_read",
                    &format!("trait={}", pending.owning_trait.fq_name()),
                );
                self.unenumerable_traits.insert(pending.owning_trait);
                self.unenumerable_members.insert(pending.member);
                continue;
            };
            let mut matches = methods
                .iter()
                .filter(|method| method.name == pending.name && method.arity == pending.arity);
            let Some(declaration) = matches.next() else {
                // Rust requires every member of a trait impl to answer a member
                // the trait declares, so an unmatched member means this pass
                // read the trait's method table incompletely.
                note_disqualified(
                    "unmatched_impl_member",
                    &format!(
                        "trait={} member={}",
                        pending.owning_trait.fq_name(),
                        pending.name
                    ),
                );
                self.unenumerable_traits.insert(pending.owning_trait);
                self.unenumerable_members.insert(pending.member);
                continue;
            };
            if matches.next().is_some() {
                note_disqualified(
                    "ambiguous_impl_member",
                    &format!(
                        "trait={} member={}",
                        pending.owning_trait.fq_name(),
                        pending.name
                    ),
                );
                self.unenumerable_traits.insert(pending.owning_trait);
                self.unenumerable_members.insert(pending.member);
                continue;
            }
            member_implements
                .entry(pending.member.clone())
                .or_default()
                .push(RustMemberFamilyEdge {
                    member: declaration.unit.clone(),
                    owner: pending.owning_trait.clone(),
                });
            member_implemented_by
                .entry(declaration.unit.clone())
                .or_default()
                .push(RustMemberFamilyEdge {
                    member: pending.member.clone(),
                    owner: pending.implementer,
                });
            self.member_trait
                .insert(pending.member, pending.owning_trait);
        }

        let order = |edges: &mut Vec<RustMemberFamilyEdge>| {
            edges.sort_by(|left, right| {
                left.member
                    .cmp(&right.member)
                    .then_with(|| left.owner.cmp(&right.owner))
            });
            edges.dedup();
        };
        for edges in member_implements.values_mut() {
            order(edges);
        }
        for edges in member_implemented_by.values_mut() {
            order(edges);
        }

        let index = RustHierarchyIndex {
            direct_ancestors: self.direct_ancestors,
            direct_descendants: self.direct_descendants,
            relations: self.relations,
            member_implements,
            member_implemented_by,
            member_trait: self.member_trait,
            unenumerable_traits: self.unenumerable_traits,
            unenumerable_members: self.unenumerable_members,
            enumeration_complete: self.enumeration_complete,
        };
        note_disqualified(
            "index_summary",
            &format!(
                "enumeration_complete={} ancestors={} descendants={} relations={} \
member_trait={} member_implements={} member_implemented_by={} \
unenumerable_traits={} unenumerable_members={} unresolved_trait_identifiers={}",
                index.enumeration_complete,
                index.direct_ancestors.len(),
                index.direct_descendants.len(),
                index.relations.len(),
                index.member_trait.len(),
                index.member_implements.len(),
                index.member_implemented_by.len(),
                index.unenumerable_traits.len(),
                index.unenumerable_members.len(),
                self.unresolved_trait_identifiers.len(),
            ),
        );
        index
    }
}

pub(crate) fn source_type_identifier(ty: &RustTypeSourceFact) -> Option<&str> {
    match &ty.shape {
        RustTypeSourceShape::Path { segments, .. } => {
            segments.last().map(|segment| segment.name.as_str())
        }
        RustTypeSourceShape::Unsupported { .. } | RustTypeSourceShape::Compound { .. } => None,
    }
}

/// Identify an impl target rooted in one of the impl's declared type
/// parameters before nominal lookup can mistake that name for a workspace
/// declaration. A bare or reference-wrapped parameter is blanket; a qualified
/// use such as `T::Assoc`, or another wrapper, is unsupported generic syntax.
fn generic_impl_target_is_dependent(
    generic_parameters: &[RustGenericParameterSourceFact],
    target: &RustTypeSourceFact,
) -> bool {
    let RustTypeSourceShape::Path {
        leading_absolute,
        segments,
    } = &target.shape
    else {
        return false;
    };
    let Some(root) = segments.first() else {
        return false;
    };
    if *leading_absolute {
        return false;
    }
    generic_parameters.iter().any(|parameter| {
        parameter.kind == "type_parameter"
            && parameter
                .name
                .as_ref()
                .is_some_and(|name| name.name.as_str() == root.name.as_str())
    })
}

pub fn canonical_rust_hierarchy_type(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    unit: CodeUnit,
) -> Result<Option<CodeUnit>, RustCargoRouteError> {
    // A namespace-only external impl owner already names its canonical type;
    // there is no local alias declaration to follow. An indexed declaration
    // still must supply canonical properties below.
    if !rust.declares(unit.source(), &unit) {
        return Ok(Some(unit));
    }
    let properties = rust.declaration_source_properties(unit.source(), &|| true)?;
    let properties = properties
        .get(&unit)
        .ok_or(RustCargoRouteError::Unavailable)?;
    if !properties
        .iter()
        .any(|property| property.kind == RustDeclarationKind::TypeAlias)
    {
        return Ok(Some(unit));
    }
    if properties
        .iter()
        .any(|property| property.kind != RustDeclarationKind::TypeAlias)
    {
        return Ok(None);
    }
    let facts = rust.canonical_rust_hierarchy_source_facts(unit.source(), &|| true)?;
    let contexts = RustSourceContextIndex::new(&facts, &|| true)?;
    let aliases: HashMap<_, _> = facts
        .items
        .aliases
        .iter()
        .map(|alias| (alias.declaration, alias))
        .collect();
    let types: HashMap<_, _> = facts.types.iter().map(|ty| (ty.occurrence, ty)).collect();
    let syntax: HashMap<_, _> = facts
        .items
        .syntax
        .iter()
        .map(|syntax| (syntax.occurrence, syntax.has_error))
        .collect();
    let mut resolved = None;
    for property in properties {
        let alias = aliases
            .get(&property.declaration)
            .ok_or(RustCargoRouteError::Unavailable)?;
        // Legacy hierarchy aliases were primary-tree declarations. Retaining
        // raw macro source facts does not by itself expand that admission.
        if !contexts.is_primary(&facts, alias.context)? {
            continue;
        }
        let declaration = &facts.declarations[alias.declaration.index()];
        if syntax.get(&declaration.occurrence) != Some(&false) {
            return Ok(None);
        }
        let Some(target) = alias.target_type else {
            return Ok(None);
        };
        let target = types
            .get(&target)
            .expect("published alias target has a type source fact");
        let binder = contexts.visible_import_binder(&facts, alias.context, &|| true)?;
        let Some(candidate) = resolve_rust_hierarchy_source_ref(
            rust,
            token,
            unit.source(),
            &contexts,
            &facts,
            alias.context,
            &binder,
            target,
            |candidate| {
                Ok(is_rust_struct_declaration(rust, candidate)?
                    || is_rust_enum_declaration(rust, candidate)?)
            },
        )?
        else {
            return Ok(None);
        };
        if resolved
            .as_ref()
            .is_some_and(|previous| previous != &candidate)
        {
            return Ok(None);
        }
        resolved = Some(candidate);
    }
    Ok(resolved)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_rust_hierarchy_source_ref<F>(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    contexts: &RustSourceContextIndex,
    facts: &RustHierarchySourceFacts,
    context: SourceOccurrenceId,
    binder: &ImportBinder,
    ty: &RustTypeSourceFact,
    predicate: F,
) -> Result<Option<CodeUnit>, RustCargoRouteError>
where
    F: Fn(&CodeUnit) -> Result<bool, RustCargoRouteError>,
{
    // Hierarchy's nominal projection peels references, not pointers or
    // collection wrappers. Preserve generic qualifier placement as well.
    if ty
        .wrappers
        .iter()
        .any(|wrapper| wrapper.kind != RustTypeWrapperSourceKind::Reference)
    {
        return Ok(None);
    }
    let Some(segments) = crate::type_syntax::declaration_owner_path(ty) else {
        return Ok(None);
    };
    let RustTypeSourceShape::Path {
        leading_absolute, ..
    } = &ty.shape
    else {
        unreachable!("declaration owner path requires a structured path");
    };
    let (terminal, prefix) = segments.split_last().expect("nominal path has a terminal");
    let name = terminal.name.as_str();
    let module_path = contexts.module_path(facts, context, &|| true)?;
    let local_module = module_path.join(".");
    let file_package = crate::declarations::rust_package_name(file);
    let lexical_package = if local_module.is_empty() {
        file_package
    } else {
        join_rust_fqn(&file_package, &local_module)
    };
    let mut candidates = Vec::new();
    if let Some((head, tail)) = prefix.split_first() {
        let namespace = (!leading_absolute)
            .then(|| binder.bindings.get(&head.name))
            .flatten()
            .filter(|binding| matches!(binding.kind, ImportKind::Namespace));
        let crate_package = rust_crate_root_package(file);
        let package = if let Some(binding) = namespace {
            // The binder owns a semantic module identity. Resolve that base
            // through the shared helper, then append the source-owned tail.
            resolve_rust_module_path_with_crate(
                &lexical_package,
                &crate_package,
                &binding.module_specifier,
            )
            .map(|mut package| {
                for segment in tail {
                    if !package.is_empty() {
                        package.push('.');
                    }
                    package.push_str(&segment.name);
                }
                package
            })
        } else {
            let segments: Vec<_> = prefix.iter().map(|segment| segment.name.as_str()).collect();
            resolve_rust_module_segments_with_crate(&lexical_package, &crate_package, &segments)
        };
        if let Some(package) = package {
            candidates.extend(units_in_package(rust, token, file, &package, name)?);
        }
    } else if !leading_absolute {
        let short_name = join_rust_fqn(&local_module, name);
        candidates.extend(
            rust.declarations_named(file, name)
                .into_iter()
                .filter(|unit| unit.short_name() == short_name),
        );
        candidates.extend(imported_units(rust, token, file, binder, name)?);
        if candidates.is_empty() {
            candidates.extend(lexically_imported_units(
                rust,
                token,
                file,
                binder,
                &lexical_package,
                name,
            )?);
        }
    }
    candidates.sort();
    candidates.dedup();
    let mut resolved = None;
    for candidate in candidates {
        if predicate(&candidate)? {
            if resolved.is_some() {
                return Ok(None);
            }
            resolved = Some(candidate);
        }
    }
    Ok(resolved)
}

fn join_rust_fqn(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}
