use crate::declarations::rust_node_text;
use crate::graph_support::{
    RustFactSource, inspect_rust_named_declaration_node, is_rust_enum_declaration,
    is_rust_struct_declaration, is_rust_trait_declaration, is_rust_type_alias_declaration,
    resolve_imported_export_from_binder, resolve_module_files,
};
use crate::imports::{resolve_rust_module_path_with_crate, rust_crate_root_package};
use crate::lexical_scope::{parse_rust_tree, visible_import_binder_at};
use crate::usage::exported_targets_from_files;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

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
    /// Whether the pass saw the whole workspace. False when a file did not
    /// read or parse, or the pair cap fired, in which case no member's family
    /// can be stated as exhaustive.
    enumeration_complete: bool,
}

impl RustHierarchyIndex {
    /// One member's complete trait family, or the honest reason this index
    /// cannot state it.
    pub fn member_family(&self, member: &CodeUnit) -> RustMemberFamily {
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

pub fn rust_trait_for_impl_member(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    member: &CodeUnit,
) -> Option<CodeUnit> {
    let source = rust.project().read_source(member.source()).ok()?;
    let tree = parse_rust_tree(&source)?;
    inspect_rust_named_declaration_node(
        rust.code_units(),
        member,
        tree.root_node(),
        &source,
        |declaration, source| {
            let mut ancestor = declaration.parent();
            let impl_item = loop {
                let candidate = ancestor?;
                if candidate.kind() == "impl_item" {
                    break candidate;
                }
                ancestor = candidate.parent();
            };
            let (trait_ref, _) = trait_impl_parts(impl_item, source)?;
            let binder = visible_import_binder_at(source, impl_item.start_byte());
            resolve_rust_hierarchy_trait_ref(
                rust,
                token,
                member.source(),
                source,
                impl_item,
                &binder,
                trait_ref,
            )
        },
    )?
}

pub fn resolve_rust_hierarchy_trait_ref(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    binder: &ImportBinder,
    raw: &str,
) -> Option<CodeUnit> {
    resolve_rust_hierarchy_ref(rust, token, file, source, impl_item, binder, raw, |unit| {
        is_rust_trait_declaration(rust.code_units(), unit)
    })
}

pub fn resolve_rust_hierarchy_type_ref(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    binder: &ImportBinder,
    raw: &str,
) -> Option<CodeUnit> {
    resolve_rust_hierarchy_ref(rust, token, file, source, impl_item, binder, raw, |unit| {
        is_rust_struct_declaration(rust.code_units(), unit)
            || is_rust_enum_declaration(rust.code_units(), unit)
            || is_rust_type_alias_declaration(rust.code_units(), unit)
    })
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_rust_hierarchy_ref<F>(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    binder: &ImportBinder,
    raw: &str,
    predicate: F,
) -> Option<CodeUnit>
where
    F: Fn(&CodeUnit) -> bool,
{
    let normalized = normalize_type_ref(raw)?;
    let lexical_package = lexical_package_name(file, impl_item, source);
    let mut candidates = Vec::new();

    if let Some((module_specifier, imported_name)) = normalized.rsplit_once("::") {
        candidates.extend(resolve_units_in_module(
            rust,
            token,
            file,
            binder,
            &lexical_package,
            module_specifier,
            imported_name,
        ));
    } else {
        candidates.extend(same_module_declarations(
            rust, file, source, impl_item, normalized,
        ));
        candidates.extend(imported_units(rust, token, file, binder, normalized));
        if candidates.is_empty() {
            candidates.extend(lexically_imported_units(
                rust,
                token,
                file,
                binder,
                &lexical_package,
                normalized,
            ));
        }
    }

    // Ambiguity means *two different declarations*, not two routes to one. A type
    // declared in this file and also re-exported by its parent module (`pub use
    // self::zip::Zip;`) is collected twice when the file glob-imports that parent
    // (`use super::*;`): once locally and once through the binder. Deduplicate by
    // declaration identity so route multiplicity does not discard the impl edge
    // (issue #1750).
    candidates.sort();
    candidates.dedup();
    let mut matches = candidates.into_iter().filter(predicate);
    let resolved = matches.next()?;
    matches.next().is_none().then_some(resolved)
}

pub fn resolve_units_in_module(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    lexical_package: &str,
    module_specifier: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let Some(resolved_package) =
        resolve_scoped_module_package(file, binder, lexical_package, module_specifier)
    else {
        return Vec::new();
    };
    let fq_name = join_rust_fqn(&resolved_package, name);
    let mut candidates: Vec<_> = rust.definitions(&fq_name).collect();
    if !candidates.is_empty() {
        candidates.sort();
        candidates.dedup();
        return candidates;
    }

    let resolved_module = resolved_package.replace('.', "::");
    let mut candidates = Vec::new();
    let module_files = resolve_module_files(rust, token, file, &resolved_module);
    candidates.extend(units_from_export_targets(
        rust,
        exported_targets_from_files(rust, token, &module_files, name).into_iter(),
    ));

    if candidates.is_empty() {
        candidates.extend(module_files.iter().flat_map(|module_file| {
            rust.declarations(module_file)
                .into_iter()
                .filter(move |unit| unit.identifier() == name)
        }));
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn resolve_scoped_module_package(
    file: &ProjectFile,
    binder: &ImportBinder,
    lexical_package: &str,
    module_specifier: &str,
) -> Option<String> {
    let expanded = if let Some((head, tail)) = module_specifier.split_once("::") {
        binder
            .bindings
            .get(head)
            .filter(|binding| matches!(binding.kind, ImportKind::Namespace))
            .map(|binding| format!("{}::{tail}", binding.module_specifier))
            .unwrap_or_else(|| module_specifier.to_string())
    } else {
        binder
            .bindings
            .get(module_specifier)
            .filter(|binding| matches!(binding.kind, ImportKind::Namespace))
            .map(|binding| binding.module_specifier.clone())
            .unwrap_or_else(|| module_specifier.to_string())
    };
    let crate_package = rust_crate_root_package(file);
    resolve_rust_module_path_with_crate(lexical_package, &crate_package, &expanded)
}

pub fn same_module_declarations(
    rust: &dyn RustFactSource,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let short_name = module_scoped_short_name(impl_item, source, name);
    rust.declarations(file)
        .into_iter()
        .filter(|unit| unit.identifier() == name && unit.short_name() == short_name)
        .collect()
}

pub fn imported_units(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<CodeUnit> {
    let targets = resolve_imported_export_from_binder(rust, token, file, binder, reference);
    units_from_export_targets(rust, targets.into_iter())
}

/// The declarations a `use` visible at the impl site binds, resolved against
/// the *lexical* module the impl is written in.
///
/// [`imported_units`] anchors every binding's module specifier at the file's
/// own package, which is right for a `use` at file scope and wrong for one
/// inside an inline module: `use super::*` written in
/// `mod tests { ... }` names the module the file itself is, not the file's
/// parent, so a trait declared beside the inline module was never found and
/// every `impl Trait for T` inside it stayed unresolved -- which is what makes
/// a trait such as rig's `Tool` unenumerable even after every cross-crate
/// reference to it resolves. The qualified branch of
/// [`resolve_rust_hierarchy_ref`] already anchors at `lexical_package`; this
/// gives the unqualified branch the same anchor.
///
/// Consulted only when nothing nearer answered, because that is Rust's own
/// precedence: a declaration in the impl's own module, and a name an explicit
/// `use` binds, both shadow a glob import.
fn lexically_imported_units(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    lexical_package: &str,
    reference: &str,
) -> Vec<CodeUnit> {
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
        units.extend(resolve_units_in_module(
            rust,
            token,
            file,
            binder,
            lexical_package,
            &binding.module_specifier,
            imported_name,
        ));
    }
    units.sort();
    units.dedup();
    units
}

pub fn units_from_export_targets(
    rust: &dyn RustFactSource,
    targets: impl Iterator<Item = (ProjectFile, String)>,
) -> Vec<CodeUnit> {
    let mut units: Vec<_> = targets
        .flat_map(|(file, name)| {
            rust.declarations(&file)
                .into_iter()
                .filter(move |unit| unit.identifier() == name)
        })
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
    arity: usize,
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
    arity: usize,
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
    /// The terminal identifier of every impl trait reference this pass could
    /// not resolve to a workspace trait. A trait of that name is not
    /// exhaustively enumerated, because one of the impls naming it was never
    /// attributed to any trait.
    unresolved_trait_identifiers: HashSet<String>,
    enumeration_complete: bool,
}

impl RustHierarchyIndex {
    pub fn build(rust: &dyn RustFactSource, token: QueryToken<'_>) -> Self {
        let _scope = brokk_bifrost_core::profiling::scope("RustHierarchyIndex::build");
        let mut builder = RustHierarchyBuilder {
            enumeration_complete: true,
            ..RustHierarchyBuilder::default()
        };

        for file in rust.get_analyzed_files() {
            let Ok(source) = rust.project().read_source(&file) else {
                builder.enumeration_complete = false;
                continue;
            };
            let Some(tree) = parse_rust_tree(&source) else {
                builder.enumeration_complete = false;
                continue;
            };
            let declarations = declarations_by_range(rust, &file);

            for trait_item in named_nodes_of_kind(tree.root_node(), "trait_item") {
                builder.record_trait_methods(&declarations, trait_item, &source);
            }
            for macro_invocation in named_nodes_of_kind(tree.root_node(), "macro_invocation") {
                builder.record_macro_expansion(rust, token, &file, &source, macro_invocation);
            }
            for impl_item in named_nodes_of_kind(tree.root_node(), "impl_item") {
                let Some((trait_ref, implementer_ref)) = trait_impl_parts(impl_item, &source)
                else {
                    continue;
                };
                let binder = visible_import_binder_at(&source, impl_item.start_byte());
                let Some(trait_unit) = resolve_rust_hierarchy_trait_ref(
                    rust, token, &file, &source, impl_item, &binder, trait_ref,
                ) else {
                    if let Some(identifier) = trait_reference_identifier(trait_ref) {
                        note_disqualified(
                            "unresolved_trait_ref",
                            &format!("ident={identifier} file={file:?}"),
                        );
                        builder
                            .unresolved_trait_identifiers
                            .insert(identifier.to_string());
                    }
                    continue;
                };
                if is_blanket_impl(impl_item, &source) {
                    // Check the implemented type against the impl's own AST
                    // binders before workspace resolution. A workspace type
                    // may share the binder's name, but it is not the type this
                    // blanket implementation names.
                    note_disqualified("blanket_impl", &format!("trait={}", trait_unit.fq_name()));
                    builder.unenumerable_traits.insert(trait_unit);
                    continue;
                }
                let Some(implementer) = resolve_rust_hierarchy_type_ref(
                    rust,
                    token,
                    &file,
                    &source,
                    impl_item,
                    &binder,
                    implementer_ref,
                )
                .and_then(|unit| canonical_rust_hierarchy_type(rust, token, unit)) else {
                    // The impl exists and names this trait, but nothing in the
                    // workspace answers for the type it implements it for. The
                    // trait's implementation set is therefore not exhaustive.
                    note_disqualified(
                        "unresolved_impl_type",
                        &format!("trait={} file={file:?}", trait_unit.fq_name()),
                    );
                    builder.unenumerable_traits.insert(trait_unit);
                    continue;
                };

                let ancestors = builder
                    .direct_ancestors
                    .entry(implementer.clone())
                    .or_default();
                if !ancestors.contains(&trait_unit) {
                    ancestors.push(trait_unit.clone());
                }
                builder
                    .direct_descendants
                    .entry(trait_unit.clone())
                    .or_default()
                    .insert(implementer.clone());
                builder.relations.push(TypeRelation {
                    from: implementer.clone(),
                    to: trait_unit.clone(),
                    kind: TypeRelationKind::TraitImplementation,
                });

                builder.record_impl_members(
                    &declarations,
                    impl_item,
                    &source,
                    &trait_unit,
                    &implementer,
                );
            }
        }

        builder.finish()
    }
}

impl RustHierarchyBuilder {
    /// Record the methods one `trait_item` declares, so that the pairing pass
    /// can join an impl member to the exact declaration it answers.
    ///
    /// A trait body member this index cannot join to a `CodeUnit`, and any
    /// macro invocation in a trait body, makes the trait's own method table
    /// unknown: the trait is marked unenumerable rather than enumerated from
    /// the methods that happened to be readable.
    fn record_trait_methods(
        &mut self,
        declarations: &HashMap<(usize, usize), CodeUnit>,
        trait_item: Node<'_>,
        source: &str,
    ) {
        let Some(trait_unit) = declarations
            .get(&(trait_item.start_byte(), trait_item.end_byte()))
            .filter(|unit| unit.is_class())
        else {
            return;
        };
        let Some(body) = trait_item.child_by_field_name("body") else {
            return;
        };
        let mut methods = Vec::new();
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            match child.kind() {
                "function_item" | "function_signature_item" => {
                    let Some(name) = declaration_name(child, source) else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    let Some(unit) = declarations
                        .get(&(child.start_byte(), child.end_byte()))
                        .filter(|unit| unit.is_function())
                    else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    methods.push(TraitMethod {
                        name: name.to_string(),
                        arity: declared_arity(child),
                        unit: unit.clone(),
                    });
                }
                // A macro in a trait body can declare members this pass never
                // sees, so the trait's method table is not known to be whole.
                "macro_invocation" => {
                    note_disqualified(
                        "macro_in_trait_body",
                        &format!("trait={}", trait_unit.fq_name()),
                    );
                    self.unenumerable_traits.insert(trait_unit.clone());
                }
                _ => {}
            }
        }
        for method in &methods {
            self.member_trait
                .insert(method.unit.clone(), trait_unit.clone());
        }
        self.trait_methods
            .entry(trait_unit.clone())
            .or_default()
            .extend(methods);
    }

    /// Record the members one resolved `impl Trait for Type` block declares.
    fn record_impl_members(
        &mut self,
        declarations: &HashMap<(usize, usize), CodeUnit>,
        impl_item: Node<'_>,
        source: &str,
        trait_unit: &CodeUnit,
        implementer: &CodeUnit,
    ) {
        let Some(body) = impl_item.child_by_field_name("body") else {
            return;
        };
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            match child.kind() {
                "function_item" => {
                    let Some(name) = declaration_name(child, source) else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    let Some(member) = declarations
                        .get(&(child.start_byte(), child.end_byte()))
                        .filter(|unit| unit.is_function())
                    else {
                        self.unenumerable_traits.insert(trait_unit.clone());
                        continue;
                    };
                    if self.pending.len() >= MAX_MEMBER_PAIRS {
                        self.enumeration_complete = false;
                        return;
                    }
                    self.pending.push(PendingImplMember {
                        owning_trait: trait_unit.clone(),
                        implementer: implementer.clone(),
                        member: member.clone(),
                        name: name.to_string(),
                        arity: declared_arity(child),
                    });
                }
                // A macro in a trait impl body can supply members this pass
                // never sees.
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

    /// Account for the trait impls that live inside a macro's token tree.
    ///
    /// The declaration walk reparses an item-position macro's token tree and
    /// indexes the items it finds, so such an impl *is* part of the indexed
    /// workspace even though it is not an `impl_item` of the file's own parse.
    /// This pass does not enumerate those members; it marks the traits they
    /// name so no family claims to be exhaustive over an impl it cannot read.
    fn record_macro_expansion(
        &mut self,
        rust: &dyn RustFactSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
        macro_invocation: Node<'_>,
    ) {
        if !macro_invocation
            .parent()
            .is_some_and(|parent| matches!(parent.kind(), "source_file" | "declaration_list"))
        {
            return;
        }
        let Some(arguments) =
            crate::declarations::rust_macro_invocation_arguments(macro_invocation)
        else {
            return;
        };
        let Some((start, end)) = crate::declarations::rust_macro_token_tree_interior(arguments)
        else {
            return;
        };
        let Some(tree) = crate::lexical_scope::parse_rust_region_tree(source, start, end) else {
            return;
        };
        let binder = visible_import_binder_at(source, macro_invocation.start_byte());
        for impl_item in named_nodes_of_kind(tree.root_node(), "impl_item") {
            let Some((trait_ref, _)) = trait_impl_parts(impl_item, source) else {
                continue;
            };
            match resolve_rust_hierarchy_trait_ref(
                rust, token, file, source, impl_item, &binder, trait_ref,
            ) {
                Some(trait_unit) => {
                    note_disqualified(
                        "macro_item_impl",
                        &format!("trait={}", trait_unit.fq_name()),
                    );
                    self.unenumerable_traits.insert(trait_unit);
                }
                None => {
                    if let Some(identifier) = trait_reference_identifier(trait_ref) {
                        self.unresolved_trait_identifiers
                            .insert(identifier.to_string());
                    }
                }
            }
        }
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

        RustHierarchyIndex {
            direct_ancestors: self.direct_ancestors,
            direct_descendants: self.direct_descendants,
            relations: self.relations,
            member_implements,
            member_implemented_by,
            member_trait: self.member_trait,
            unenumerable_traits: self.unenumerable_traits,
            enumeration_complete: self.enumeration_complete,
        }
    }
}

/// Every declaration this index recorded for `file`, keyed by the exact byte
/// range of the node that declared it.
///
/// The join has to be exact rather than by name: a type that implements two
/// traits with a same-named method declares several members whose owner and
/// identifier agree, and only the declaration site tells them apart.
fn declarations_by_range(
    rust: &dyn RustFactSource,
    file: &ProjectFile,
) -> HashMap<(usize, usize), CodeUnit> {
    let index = rust.code_units();
    let mut by_range = HashMap::default();
    for unit in index.declarations(file) {
        for range in index.ranges(&unit) {
            let key = (range.start_byte, range.end_byte);
            if let Some(previous) = by_range.insert(key, unit.clone()) {
                debug_assert_eq!(
                    previous, unit,
                    "two declarations cannot share one exact byte range in {file:?}"
                );
            }
        }
    }
    by_range
}

fn declaration_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let name = rust_node_text(node.child_by_field_name("name")?, source).trim();
    (!name.is_empty()).then_some(name)
}

/// The number of parameters a callable declares, the `self` receiver included.
fn declared_arity(node: Node<'_>) -> usize {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return 0;
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "attribute_item")
        .count()
}

/// Whether this impl implements its trait for one of its own type parameters:
/// `impl<T: Bound> Trait for T`.
///
/// Such an impl covers every type satisfying the bound, so a workspace scan
/// cannot enumerate the trait's implementors. The check is structural -- the
/// implemented type is compared against the impl's declared type parameters --
/// because a workspace type may share a parameter's name, in which case
/// resolving the reference would otherwise name the wrong declaration.
fn is_blanket_impl(impl_item: Node<'_>, source: &str) -> bool {
    let Some((_, implementer_ref)) = trait_impl_parts(impl_item, source) else {
        return false;
    };
    let Some(implemented) = normalize_type_ref(implementer_ref) else {
        return false;
    };
    let Some(parameters) = impl_item.child_by_field_name("type_parameters") else {
        return false;
    };
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter.kind() == "type_parameter"
            && parameter
                .child_by_field_name("name")
                .is_some_and(|name| rust_node_text(name, source).trim() == implemented)
    })
}

/// The terminal identifier of an impl's trait reference, which is what a
/// workspace trait of that name would have to be named.
fn trait_reference_identifier(raw: &str) -> Option<&str> {
    let normalized = normalize_type_ref(raw)?;
    Some(normalized.rsplit("::").next().unwrap_or(normalized))
}

pub fn canonical_rust_hierarchy_type(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    unit: CodeUnit,
) -> Option<CodeUnit> {
    if !is_rust_type_alias_declaration(rust.code_units(), &unit) {
        return Some(unit);
    }
    let source = rust.project().read_source(unit.source()).ok()?;
    let tree = parse_rust_tree(&source)?;
    let alias_node = type_alias_node(tree.root_node(), &source, &unit)?;
    let target = type_alias_target_ref(alias_node, &source)
        .or_else(|| unit.signature().and_then(alias_target_text))?;
    let binder = visible_import_binder_at(&source, alias_node.start_byte());
    resolve_rust_hierarchy_ref(
        rust,
        token,
        unit.source(),
        &source,
        alias_node,
        &binder,
        target,
        |candidate| {
            is_rust_struct_declaration(rust.code_units(), candidate)
                || is_rust_enum_declaration(rust.code_units(), candidate)
        },
    )
}

fn named_nodes_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    out
}

fn trait_impl_parts<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<(&'source str, &'source str)> {
    let trait_node = node.child_by_field_name("trait")?;
    let type_node = node.child_by_field_name("type")?;
    Some((
        rust_node_text(trait_node, source).trim(),
        rust_node_text(type_node, source).trim(),
    ))
}

fn normalize_type_ref(raw: &str) -> Option<&str> {
    let mut value = raw.trim().trim_start_matches('&').trim();
    while let Some(stripped) = value.strip_prefix("mut ") {
        value = stripped.trim();
    }
    if let Some(index) = value.find('<') {
        value = &value[..index];
    }
    if value.is_empty() { None } else { Some(value) }
}

fn alias_target_text(signature: &str) -> Option<&str> {
    let rhs = signature
        .split_once('=')?
        .1
        .trim()
        .trim_end_matches(';')
        .trim();
    normalize_type_ref(rhs)
}

fn lexical_package_name(file: &ProjectFile, impl_item: Node<'_>, source: &str) -> String {
    let file_package = crate::declarations::rust_package_name(file);
    let mut modules = inline_module_path(impl_item, source);
    if file_package.is_empty() {
        modules.join(".")
    } else if modules.is_empty() {
        file_package
    } else {
        modules.insert(0, file_package);
        modules.join(".")
    }
}

fn module_scoped_short_name(impl_item: Node<'_>, source: &str, name: &str) -> String {
    let modules = inline_module_path(impl_item, source);
    if modules.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", modules.join("."), name)
    }
}

fn inline_module_path(impl_item: Node<'_>, source: &str) -> Vec<String> {
    let mut modules = Vec::new();
    let mut current = impl_item.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item"
            && let Some(name_node) = parent.child_by_field_name("name")
        {
            modules.push(rust_node_text(name_node, source).trim().to_string());
        }
        current = parent.parent();
    }
    modules.reverse();
    modules
}

fn join_rust_fqn(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

fn type_alias_node<'tree>(
    root: Node<'tree>,
    source: &str,
    alias: &CodeUnit,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_item"
            && let Some(name_node) = node.child_by_field_name("name")
        {
            let name = rust_node_text(name_node, source).trim();
            if module_scoped_short_name(node, source, name) == alias.short_name() {
                return Some(node);
            }
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn type_alias_target_ref<'source>(
    alias_node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let target_node = alias_node.child_by_field_name("type")?;
    normalize_type_ref(rust_node_text(target_node, source).trim())
}
