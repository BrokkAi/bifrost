//! The analyzer-owned half of Rust's type hierarchy: the `TypeHierarchyProvider`
//! and `MemberFamilyProvider` capability impls and the fallible memo behind
//! them.
//!
//! The index itself and every predicate it is built from live in
//! [`brokk_bifrost_rust::hierarchy`] and [`brokk_bifrost_rust::graph_support`].

use crate::analyzer::common::language_for_file;
use crate::analyzer::structural::resolution::{
    MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason, MethodFamilyRelation,
};
use crate::analyzer::usages::{MemberFamilyAnswer, MemberFamilyEdge, MemberFamilyProvider};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{CodeUnit, CodeUnitIndex, Language, TypeHierarchyProvider};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_rust::graph_support::RustCargoRouteError;
use brokk_bifrost_rust::graph_support::{
    is_rust_enum_declaration, is_rust_struct_declaration, is_rust_trait_declaration,
    is_rust_trait_impl_member_declaration, is_rust_type_alias_declaration,
    is_rust_type_member_declaration,
};
use brokk_bifrost_rust::hierarchy::{
    RustMemberFamily, RustMemberFamilyEdge, rust_direct_ancestors, rust_direct_descendants,
    rust_member_family_of,
};

use super::RustAnalyzer;

impl TypeHierarchyProvider for RustAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.direct_ancestors(code_unit) {
            Ok(ancestors) => ancestors,
            Err(error) => {
                self.record_hierarchy_error(error);
                Vec::new()
            }
        }
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) {
            return HashSet::default();
        }
        let is_trait = match is_rust_trait_declaration(self, code_unit) {
            Ok(value) => value,
            Err(error) => {
                self.record_hierarchy_error(error);
                return HashSet::default();
            }
        };
        if !is_trait {
            return HashSet::default();
        }

        let scope = AnalyzerQueryScope::new(self);
        match rust_direct_descendants(self, scope.token(), code_unit, &|| true) {
            Ok(descendants) => descendants,
            Err(error) => {
                self.record_hierarchy_error(error);
                HashSet::default()
            }
        }
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        if !self.declares(code_unit.source(), code_unit) {
            return false;
        }
        let supported: Result<bool, RustCargoRouteError> = (|| {
            Ok(is_rust_trait_declaration(self, code_unit)?
                || is_rust_struct_declaration(self, code_unit)?
                || is_rust_enum_declaration(self, code_unit)?
                || is_rust_type_alias_declaration(self, code_unit)?)
        })();
        match supported {
            Ok(value) => value,
            Err(error) => {
                self.record_hierarchy_error(error);
                false
            }
        }
    }

    fn get_direct_ancestors_within(
        &self,
        code_unit: &CodeUnit,
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> Option<Vec<CodeUnit>> {
        if scope.cancellation().is_cancelled() {
            return None;
        }
        match self.direct_ancestors(code_unit) {
            Ok(ancestors) => (!scope.cancellation().is_cancelled()).then_some(ancestors),
            Err(error) => {
                self.record_hierarchy_error(error);
                None
            }
        }
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        if scope.cancellation().is_cancelled() {
            return None;
        }
        if !self.supports_type_hierarchy(code_unit) {
            return Some(HashSet::default());
        }
        let is_trait = match is_rust_trait_declaration(self, code_unit) {
            Ok(value) => value,
            Err(error) => {
                self.record_hierarchy_error(error);
                return None;
            }
        };
        if !is_trait {
            return Some(HashSet::default());
        }
        let cancellation = scope.cancellation();
        let query = AnalyzerQueryScope::new(self);
        match rust_direct_descendants(self, query.token(), code_unit, &|| {
            !cancellation.is_cancelled()
        }) {
            Ok(descendants) => (!cancellation.is_cancelled()).then_some(descendants),
            Err(RustCargoRouteError::Cancelled) => None,
            Err(error) => {
                self.record_hierarchy_error(error);
                None
            }
        }
    }
}
/// Rust's member family: which method of a trait impl answers each method a
/// trait declares (#1721).
///
/// Rust writes the relation down. `impl Trait for Type` names both ends, and
/// [`RustHierarchyIndex::build`] already resolves both through the file's
/// import binders to exact `CodeUnit`s -- the same pass that produces the type
/// relation. The member family is that proof read one level down: inside a
/// resolved trait-impl edge, an impl member is paired with the trait method of
/// the same name and the same declared parameter count. Nothing is matched by
/// fully-qualified name or by rendered signature text, and no pair exists
/// outside a resolved trait-impl edge, so an inherent method that shares a
/// name with a trait method is not a member of the family and neither is a
/// different trait's same-named method.
///
/// `proven` means "exhaustive over the indexed workspace": every Rust file
/// read and parsed, the pair cap unfired, and the trait at the far end has no
/// implementation this pass could not attribute. A blanket impl
/// (`impl<T: Bound> Trait for T`), an impl for a type the resolver cannot
/// name, an impl whose trait reference does not resolve, a macro that can
/// contribute members to the trait or its impls -- each one makes that trait's
/// family `incomplete`, and dispatch treats an unproven family as contributing
/// no target at all. That is the correct failure mode: the call stays exactly
/// as unresolved as it already was.
///
/// One boundary is stated rather than detected. A trait impl produced by
/// expanding a macro whose token tree does not itself contain the `impl` item
/// is in no index Bifrost builds -- not the declaration index, not the type
/// relation -- so no member family can see it. "Exhaustive over the indexed
/// workspace" is exactly that scope, the same scope Go's family states.
impl MemberFamilyProvider for RustAnalyzer {
    fn member_family_capability(&self, member: &CodeUnit) -> MemberFamilyCapability {
        rust_member_family_capability(member)
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> MemberFamilyAnswer {
        rust_member_family(self, member, cancellation)
    }
}

/// What a Rust declaration's own recorded structure can discriminate.
///
/// `NameAndArity` is the measured level. Rust forbids overloading, so a trait
/// declares at most one method of a given name and an impl block of that trait
/// declares at most one member answering it; the parameter count read from the
/// declaration's `parameters` node is the structural check that the pair the
/// resolved trait-impl edge singles out is the pair the compiler would make.
/// Parameter type spellings are deliberately not compared: an impl legitimately
/// writes a concrete type where the trait writes `Self::Item` or a type
/// parameter, so comparing spellings would reject correct implementations.
pub fn rust_member_family_capability(member: &CodeUnit) -> MemberFamilyCapability {
    if language_for_file(member.source()) != Language::Rust {
        return MemberFamilyCapability::Unsupported;
    }
    MemberFamilyCapability::NameAndArity
}

/// One Rust member's family, read out of the workspace trait-impl index.
fn rust_member_family(
    analyzer: &RustAnalyzer,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    let capability = rust_member_family_capability(member);
    if capability == MemberFamilyCapability::Unsupported {
        return MemberFamilyAnswer::unsupported_answer();
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::HierarchyTruncated);
    }
    if !member.is_function() {
        match is_rust_type_member_declaration(analyzer, member) {
            Ok(true) => {}
            Ok(false) => {
                return MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod);
            }
            Err(error) => {
                analyzer.record_hierarchy_error(error);
                return MemberFamilyAnswer::incomplete(
                    capability,
                    MemberFamilyReason::HierarchyTruncated,
                );
            }
        }
    }

    let scope = AnalyzerQueryScope::new(analyzer);
    let family = match rust_member_family_of(analyzer, scope.token(), member) {
        Ok(family) => family,
        Err(error) => {
            analyzer.record_hierarchy_error(error);
            return MemberFamilyAnswer::incomplete(
                capability,
                MemberFamilyReason::HierarchyTruncated,
            );
        }
    };
    let (implements, implemented_by) = match family {
        RustMemberFamily::Proven {
            implements,
            implemented_by,
        } => (implements, implemented_by),
        RustMemberFamily::NotEnumerable => {
            return MemberFamilyAnswer::incomplete(
                capability,
                MemberFamilyReason::HierarchyTruncated,
            );
        }
        // A free function and an inherent method join no trait family, and
        // that is a complete answer: Rust dispatches an inherent method
        // statically. A member the index did not record while its declaration
        // site *is* a trait or a trait impl is a fact the index is missing,
        // not an exclusion.
        RustMemberFamily::NotTracked => {
            let associated: Result<bool, RustCargoRouteError> = (|| {
                if let Some(parent) = analyzer.parent_of(member)
                    && brokk_bifrost_rust::graph_support::is_trait_owner(analyzer, &parent)?
                {
                    return Ok(true);
                }
                is_rust_trait_impl_member_declaration(analyzer, member)
            })();
            return match associated {
                Ok(true) => {
                    MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::OwnerUnknown)
                }
                Ok(false) => {
                    MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod)
                }
                Err(error) => {
                    analyzer.record_hierarchy_error(error);
                    MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::OwnerUnknown)
                }
            };
        }
    };

    // Rust has no overloading, so the trait method a member answers is singled
    // out by its name inside the resolved trait-impl edge, with the declared
    // parameter count as the structural confirmation.
    let edge = |edge: RustMemberFamilyEdge, relation: MethodFamilyRelation| MemberFamilyEdge {
        target: edge.member,
        owner: edge.owner,
        relation,
        depth: 1,
        arity_unique: true,
    };
    let roots = if implements.is_empty() {
        vec![member.clone()]
    } else {
        let mut roots: Vec<CodeUnit> = implements.iter().map(|edge| edge.member.clone()).collect();
        roots.sort();
        roots.dedup();
        roots
    };
    let edges = implements
        .into_iter()
        .map(|value| edge(value, MethodFamilyRelation::Implements))
        .chain(
            implemented_by
                .into_iter()
                .map(|value| edge(value, MethodFamilyRelation::ImplementedBy)),
        )
        .collect();
    MemberFamilyAnswer {
        capability,
        outcome: MemberFamilyOutcome::Proven,
        reason: None,
        edges,
        roots,
    }
}

impl RustAnalyzer {
    pub(crate) fn direct_ancestors(
        &self,
        code_unit: &CodeUnit,
    ) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
        if !self.supports_type_hierarchy(code_unit) {
            return Ok(Vec::new());
        }
        let is_trait = is_rust_trait_declaration(self, code_unit)?;
        if is_trait {
            return Ok(Vec::new());
        }
        let scope = AnalyzerQueryScope::new(self);
        rust_direct_ancestors(self, scope.token(), code_unit, &|| true)
    }

    /// Legacy hierarchy capability methods cannot return a failure value. Keep
    /// that failure on the enclosing query boundary and never memoize its empty
    /// projection as a successfully built hierarchy.
    pub(crate) fn record_hierarchy_error(&self, error: RustCargoRouteError) {
        self.inner
            .record_store_error(crate::analyzer::store::StoreError::new(format!(
                "Rust hierarchy could not read canonical facts: {error:?}"
            )));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::type_relations::TypeRelationKind;
    use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language};
    use crate::test_support::AnalyzerFixture;
    use std::sync::Arc;

    pub(super) fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, RustAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    /// The trait-family edges of one relation, rendered as the declaration
    /// signatures that name each member's impl block -- which is what tells
    /// `impl Greeter for Person::fn greet` apart from the inherent
    /// `impl Person::fn greet` and from `impl Shouter for Robot::fn greet`.
    pub(super) fn family_edges(
        analyzer: &RustAnalyzer,
        member: &CodeUnit,
        relation: MethodFamilyRelation,
    ) -> Vec<String> {
        let answer = analyzer.member_family(member, None);
        assert!(
            answer.is_proven(),
            "expected a proven family for {}, got {:?} ({:?})",
            member.fq_name(),
            answer.outcome,
            answer.reason
        );
        let mut rendered: Vec<String> = answer
            .edges
            .iter()
            .filter(|edge| edge.relation == relation)
            .map(|edge| {
                edge.target
                    .signature()
                    .unwrap_or_else(|| edge.target.short_name())
                    .to_string()
            })
            .collect();
        rendered.sort();
        rendered
    }

    /// The one declaration of `fq_name` whose signature contains `needle`. A
    /// Rust trait-impl member's signature carries its impl block, so this is
    /// how a test names one of several same-named members of one type.
    pub(super) fn member_in_impl(analyzer: &RustAnalyzer, fq_name: &str, needle: &str) -> CodeUnit {
        let mut matches = analyzer
            .get_definitions(fq_name)
            .into_iter()
            .filter(|unit| unit.signature().is_some_and(|text| text.contains(needle)));
        let found = matches
            .next()
            .unwrap_or_else(|| panic!("missing declaration of {fq_name} in {needle}"));
        assert!(
            matches.next().is_none(),
            "{needle} names more than one declaration of {fq_name}"
        );
        found
    }

    pub(super) fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
        analyzer
            .get_definitions(fq_name)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
    }

    fn canonical_type(analyzer: &RustAnalyzer, unit: CodeUnit) -> Option<CodeUnit> {
        let scope = AnalyzerQueryScope::new(analyzer);
        let result = brokk_bifrost_rust::hierarchy::canonical_rust_hierarchy_type(
            analyzer,
            scope.token(),
            unit,
        )
        .expect("published canonical Rust hierarchy facts");
        assert!(
            scope.store_error().is_none(),
            "canonical type query recorded a store error"
        );
        result
    }

    /// The whole workspace's hierarchy facts, for fixtures that assert about
    /// the relation itself rather than about one question's answer.
    ///
    /// Production never reads the workspace this way any more: every question
    /// is answered from the rows and a bounded file set. These fixtures are
    /// small enough that reading every file is the clearest way to state what
    /// they are checking.
    fn workspace_hierarchy(
        analyzer: &RustAnalyzer,
    ) -> brokk_bifrost_rust::hierarchy::RustHierarchyIndex {
        let scope = AnalyzerQueryScope::new(analyzer);
        let files: Vec<_> = analyzer.get_analyzed_files().into_iter().collect();
        brokk_bifrost_rust::hierarchy::RustHierarchyIndex::read_over(
            analyzer,
            scope.token(),
            &files,
        )
        .expect("published fixture hierarchy")
    }

    fn has_trait_implementation_relation(analyzer: &RustAnalyzer, from: &str, to: &str) -> bool {
        workspace_hierarchy(analyzer)
            .relations
            .iter()
            .any(|relation| {
                relation.from.fq_name() == from
                    && relation.to.fq_name() == to
                    && relation.kind == TypeRelationKind::TraitImplementation
            })
    }

    #[test]
    fn namespace_only_impl_owner_does_not_require_an_alias_declaration() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "impl External { pub fn external_method(&self) {} }\n",
        )]);
        let file = analyzer.get_analyzed_files().into_iter().next().unwrap();
        let member = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "external_method")
            .unwrap();
        let owner = analyzer.parent_of(&member).unwrap();
        assert!(!analyzer.declarations(&file).contains(&owner));
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            brokk_bifrost_rust::hierarchy::canonical_rust_hierarchy_type(
                &analyzer,
                scope.token(),
                owner.clone()
            ),
            Ok(Some(owner)),
        );
        assert_eq!(
            analyzer.rust_trait_member_implementations(&member),
            Ok(None)
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_implementer_names_project_structured_primary_targets() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract {}
struct Item;
struct Wrapper<T>(T);
type Alias = Item;
struct Foo;
struct Bar;
impl Contract for Item {}
impl<'a> Contract for &'a Item {}
impl Contract for Wrapper<u8> {}
impl Contract for Alias {}
impl Contract for (Foo, Bar) {}
struct Negative;
impl !Contract for Negative {}
generate! { struct Generated; impl Contract for Generated {} }
"#,
        )]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            brokk_bifrost_rust::graph_support::trait_implementer_names(
                &analyzer,
                scope.token(),
                &definition(&analyzer, "Contract"),
                &|| true,
            )
            .unwrap(),
            ["Item", "Wrapper", "Alias"]
                .into_iter()
                .map(str::to_owned)
                .collect::<HashSet<_>>()
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_file_import_binder_uses_root_even_when_first_item_is_a_module() {
        let source = concat!(
            "mod nested { use wrong::Thing as Chosen; }\n",
            "use actual::Thing as Chosen;\n",
            "fn local() { use local::Thing as Chosen; }\n",
            "wrap! { use embedded::Thing as Chosen; }\n",
            "use future::Item as Later;\n",
        );
        let (fixture, analyzer) = analyzer_with_files(&[("src/lib.rs", source)]);
        let file = crate::analyzer::ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(!analyzer.declarations(&file).is_empty());
        std::fs::remove_file(file.abs_path()).unwrap();
        let binder = brokk_bifrost_rust::graph_support::canonical_rust_file_import_binder(
            &analyzer,
            &file,
            &|| true,
        )
        .unwrap();
        let chosen = binder.bindings.get("Chosen").expect("root alias");
        assert_eq!(chosen.module_specifier, "actual", "{binder:?}");
        assert_eq!(chosen.imported_name.as_deref(), Some("Thing"), "{binder:?}");
        assert!(binder.bindings.contains_key("Later"), "{binder:?}");
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_file_import_binder_distinguishes_empty_cancelled_and_unavailable() {
        let (fixture, analyzer) = analyzer_with_files(&[("src/lib.rs", "")]);
        let file = crate::analyzer::ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(matches!(
            brokk_bifrost_rust::graph_support::canonical_rust_file_import_binder(
                &analyzer,
                &file,
                &|| false
            ),
            Err(RustCargoRouteError::Cancelled)
        ));
        let binder = brokk_bifrost_rust::graph_support::canonical_rust_file_import_binder(
            &analyzer,
            &file,
            &|| true,
        )
        .unwrap();
        assert!(binder.bindings.is_empty(), "{binder:?}");
        assert!(scope.store_error().is_none());
        drop(scope);

        // Use a fresh analyzer so a successful bounded fact cache cannot mask
        // the deliberately missing publication witness.
        let (fixture, analyzer) = analyzer_with_files(&[("src/lib.rs", "use dep::Thing;")]);
        let file = crate::analyzer::ProjectFile::new(fixture.project_root(), "src/lib.rs");
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let _scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            brokk_bifrost_rust::graph_support::canonical_rust_file_import_binder(
                &analyzer,
                &file,
                &|| true
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_primary_query_keeps_occurrences_and_facts_on_one_blob() {
        use crate::analyzer::store::liveness::LivePathEntry;
        use std::cell::Cell;

        let source_a = "type Alpha = u8;";
        let source_b = "type Bravo = u8;";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", source_a)
            .file("src/other.rs", source_b)
            .build();
        let project = fixture.project_dyn();
        let context =
            crate::analyzer::tree_sitter_analyzer::ephemeral_store_context(project.as_ref())
                .unwrap();
        let live_paths = Arc::clone(&context.live_paths);
        let analyzer = RustAnalyzer::new_with_config_store_context(
            project,
            crate::analyzer::AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        let file = fixture.file("src/lib.rs");
        let oid_b = live_paths
            .snapshot()
            .oid_for_path(&fixture.file("src/other.rs"))
            .unwrap();
        let calls = Cell::new(0);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let selected = analyzer
            .canonical_rust_primary_source_at(&file, 0..source_a.len(), &|| {
                calls.set(calls.get() + 1);
                // The provider's first check precedes key capture. The store's
                // first check follows it: change the mount before reading rows.
                if calls.get() == 2 {
                    live_paths.refresh([LivePathEntry::overlay(file.clone(), oid_b)]);
                }
                true
            })
            .unwrap();
        assert!(!selected.occurrences.is_empty());
        let names: HashSet<_> = selected
            .facts
            .declaration_units
            .iter()
            .map(|(_, unit)| unit.identifier())
            .collect();
        assert!(
            names.contains("Alpha") && !names.contains("Bravo"),
            "{names:?}"
        );
        let changed = analyzer
            .canonical_rust_primary_source_at(&file, 0..source_b.len(), &|| true)
            .unwrap();
        let names: HashSet<_> = changed
            .facts
            .declaration_units
            .iter()
            .map(|(_, unit)| unit.identifier())
            .collect();
        assert!(
            names.contains("Bravo") && !names.contains("Alpha"),
            "{names:?}"
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_implementer_names_use_scoped_trait_identity() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/source.rs", "pub trait Contract<T> {}"),
            (
                "src/lib.rs",
                r#"
mod source;
mod local {
    use crate::source::Contract as Imported;
    pub struct Item;
    impl Imported<u8> for Item {}
}
mod other {
    pub trait Contract<T> {}
    pub struct Unrelated;
    impl Contract<u8> for Unrelated {}
}
"#,
            ),
        ]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            brokk_bifrost_rust::graph_support::trait_implementer_names(
                &analyzer,
                scope.token(),
                &definition(&analyzer, "source.Contract"),
                &|| true,
            )
            .unwrap(),
            ["Item".to_owned()].into_iter().collect::<HashSet<_>>()
        );
    }

    #[test]
    fn canonical_implementer_names_read_frozen_facts_without_source() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract {} struct Item; impl Contract for Item {}",
        )]);
        let owner = definition(&analyzer, "Contract");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.declarations(owner.source()).contains(&owner));
        std::fs::remove_file(owner.source().abs_path()).unwrap();
        assert_eq!(
            brokk_bifrost_rust::graph_support::trait_implementer_names(
                &analyzer,
                scope.token(),
                &owner,
                &|| true
            )
            .unwrap(),
            ["Item".to_owned()].into_iter().collect::<HashSet<_>>()
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_implementer_names_do_not_cache_cancellation_as_empty() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract {} struct Item; impl Contract for Item {}",
        )]);
        let owner = definition(&analyzer, "Contract");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            brokk_bifrost_rust::graph_support::trait_implementer_names(
                &analyzer,
                scope.token(),
                &owner,
                &|| false
            ),
            Err(RustCargoRouteError::Cancelled)
        );
        assert_eq!(
            brokk_bifrost_rust::graph_support::trait_implementer_names(
                &analyzer,
                scope.token(),
                &owner,
                &|| true
            )
            .unwrap(),
            ["Item".to_owned()].into_iter().collect::<HashSet<_>>()
        );
    }

    #[test]
    fn canonical_implementer_names_propagate_unavailable_publication() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract {} struct Item; impl Contract for Item {}",
        )]);
        let owner = definition(&analyzer, "Contract");
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            brokk_bifrost_rust::graph_support::trait_implementer_names(
                &analyzer,
                scope.token(),
                &owner,
                &|| true
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_trait_member_enumeration_keeps_methods_and_associated_types() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "src/contracts.rs",
                "pub trait Contract { fn run(&self); type Output; const LIMIT: usize; }",
            ),
            (
                "src/lib.rs",
                "mod contracts; use contracts::Contract as Imported; struct Item;\n\
             impl Imported for Item { fn run(&self) {} type Output = Item; const LIMIT: usize = 1; }",
            ),
        ]);
        for (member, implementation) in [
            ("contracts.Contract.run", "Item.run"),
            ("contracts.Contract.Output", "Item.Output"),
        ] {
            assert_eq!(
                analyzer
                    .rust_trait_member_implementations(&definition(&analyzer, member))
                    .unwrap(),
                Some(vec![definition(&analyzer, implementation)]),
                "{member}"
            );
        }
        assert_eq!(
            analyzer
                .rust_trait_member_implementations(&definition(
                    &analyzer,
                    "contracts.Contract.LIMIT"
                ))
                .unwrap(),
            None
        );
    }

    #[test]
    fn canonical_trait_member_enumeration_uses_scoped_structured_heads() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
mod left {
    pub trait Contract<T> { fn run(&self); }
    pub struct Item;
    impl Contract<u8> for Item { fn run(&self) {} }
}
mod right {
    pub trait Contract<T> { fn run(&self); }
    pub struct Item;
    impl Contract<u8> for Item { fn run(&self) {} }
}
"#,
        )]);
        for module in ["left", "right"] {
            assert_eq!(
                analyzer
                    .rust_trait_member_implementations(&definition(
                        &analyzer,
                        &format!("{module}.Contract.run")
                    ))
                    .unwrap(),
                Some(vec![definition(&analyzer, &format!("{module}.Item.run"))])
            );
        }
    }

    #[test]
    fn canonical_trait_member_enumeration_deduplicates_primary_source_alternatives() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); }
struct Item;
#[cfg(first)] impl Contract for Item { fn run(&self) {} }
#[cfg(second)] impl Contract for Item { fn run(&self) {} }
generate! { struct Generated; impl Contract for Generated { fn run(&self) {} } }
struct Negative;
impl !Contract for Negative { fn run(&self) {} }
"#,
        )]);
        assert_eq!(
            analyzer
                .rust_trait_member_implementations(&definition(&analyzer, "Contract.run"))
                .unwrap(),
            Some(vec![definition(&analyzer, "Item.run")])
        );
    }

    #[test]
    fn canonical_trait_member_enumeration_preserves_known_malformed_body_members() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn known(&self); type Output; }
struct Item;
impl Contract for Item {
    fn known(&self) {}
    type Output = Item;
    fn malformed(&self, value: );
}
"#,
        )]);
        for (member, implementation) in [
            ("Contract.known", "Item.known"),
            ("Contract.Output", "Item.Output"),
        ] {
            assert_eq!(
                analyzer
                    .rust_trait_member_implementations(&definition(&analyzer, member))
                    .unwrap(),
                Some(vec![definition(&analyzer, implementation)])
            );
        }
    }

    #[test]
    fn canonical_trait_member_enumeration_does_not_reopen_frozen_source() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract { fn run(&self); } struct Item; impl Contract for Item { fn run(&self) {} }",
        )]);
        let member = definition(&analyzer, "Contract.run");
        let implementation = definition(&analyzer, "Item.run");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.declarations(member.source()).contains(&member));
        std::fs::remove_file(member.source().abs_path()).unwrap();
        assert_eq!(
            brokk_bifrost_rust::graph_support::rust_trait_member_implementations(
                &analyzer,
                scope.token(),
                &member
            )
            .unwrap(),
            Some(vec![implementation])
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_trait_member_enumeration_propagates_unavailable_publication() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract { fn run(&self); } struct Item; impl Contract for Item { fn run(&self) {} }",
        )]);
        let member = definition(&analyzer, "Contract.run");
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        assert!(analyzer.rust_trait_member_implementations(&member).is_err());
    }

    #[test]
    fn canonical_impl_member_owners_include_methods_and_associated_fields() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); const LIMIT: usize; type Output; }
struct Item;
impl Contract for Item {
    fn run(&self) {}
    const LIMIT: usize = 1;
    type Output = Item;
}
impl Item { fn inherent(&self) {} }
"#,
        )]);
        let expected = definition(&analyzer, "Contract");
        let scope = AnalyzerQueryScope::new(&analyzer);
        for name in ["Item.run", "Item.LIMIT", "Item.Output"] {
            assert_eq!(
                brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
                    &analyzer,
                    scope.token(),
                    &definition(&analyzer, name)
                )
                .unwrap(),
                Some(expected.clone()),
                "{name}"
            );
        }
        assert_eq!(
            brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
                &analyzer,
                scope.token(),
                &definition(&analyzer, "Item.inherent")
            )
            .unwrap(),
            None
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_impl_member_owners_include_nested_macro_source() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); const LIMIT: usize; }
outer! { inner! {
    struct Item;
    impl Contract for Item {
        fn run(&self) {}
        const LIMIT: usize = 1;
    }
} }
"#,
        )]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        for name in ["Item.run", "Item.LIMIT"] {
            assert_eq!(
                brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
                    &analyzer,
                    scope.token(),
                    &definition(&analyzer, name)
                )
                .unwrap(),
                Some(definition(&analyzer, "Contract")),
                "{name}"
            );
        }
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_impl_member_owners_keep_primary_imports_for_embedded_trees() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/source.rs", "pub trait Contract { fn run(&self); }"),
            ("src/other.rs", "pub trait Contract { fn run(&self); }"),
            (
                "src/lib.rs",
                r#"
mod source;
mod other;
mod surrounding {
    use crate::source::Contract;
    outer! { inner! {
        use crate::other::Contract;
        pub struct Item;
        impl Contract for Item { fn run(&self) {} }
    } }
}
"#,
            ),
        ]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
                &analyzer,
                scope.token(),
                &definition(&analyzer, "surrounding.Item.run")
            )
            .unwrap(),
            Some(definition(&analyzer, "source.Contract"))
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_impl_member_owners_require_source_alternatives_to_agree() {
        for (second_module, agrees) in [("source", true), ("other", false)] {
            let source = format!(
                r#"
mod source;
mod other;
#[cfg(feature = "first")]
mod local {{
    use crate::source::Contract;
    pub struct Item;
    impl Contract for Item {{ fn run(&self) {{}} }}
}}
#[cfg(not(feature = "first"))]
mod local {{
    use crate::{second_module}::Contract;
    pub struct Item;
    impl Contract for Item {{ fn run(&self) {{}} }}
}}
"#
            );
            let (_fixture, analyzer) = analyzer_with_files(&[
                ("src/lib.rs", &source),
                ("src/source.rs", "pub trait Contract { fn run(&self); }"),
                ("src/other.rs", "pub trait Contract { fn run(&self); }"),
            ]);
            let scope = AnalyzerQueryScope::new(&analyzer);
            let expected = agrees.then(|| definition(&analyzer, "source.Contract"));
            assert_eq!(
                brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
                    &analyzer,
                    scope.token(),
                    &definition(&analyzer, "local.Item.run")
                )
                .unwrap(),
                expected,
                "second module: {second_module}"
            );
            assert!(scope.store_error().is_none());
        }
    }

    #[test]
    fn canonical_impl_member_owner_does_not_reopen_source_in_frozen_query() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract { fn run(&self); } struct Item; impl Contract for Item { fn run(&self) {} }",
        )]);
        let member = definition(&analyzer, "Item.run");
        let expected = definition(&analyzer, "Contract");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.declarations(member.source()).contains(&member));
        std::fs::remove_file(member.source().abs_path()).unwrap();
        assert_eq!(
            brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
                &analyzer,
                scope.token(),
                &member
            )
            .unwrap(),
            Some(expected)
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_aliases_resolve_one_hop_to_structs_and_enums_only() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub struct Item;
pub enum Choice { A }
pub type ItemAlias = Item;
pub type ChoiceAlias = Choice;
pub type AliasToAlias = ItemAlias;
pub struct Generic<T>(T);
pub type GenericAlias = Generic<u8>;
"#,
        )]);

        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "ItemAlias")),
            Some(definition(&analyzer, "Item"))
        );
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "ChoiceAlias")),
            Some(definition(&analyzer, "Choice"))
        );
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "GenericAlias")),
            Some(definition(&analyzer, "Generic"))
        );
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "AliasToAlias")),
            None
        );
    }

    #[test]
    fn canonical_alias_resolution_does_not_reopen_source_in_frozen_query() {
        let (_fixture, analyzer) =
            analyzer_with_files(&[("src/lib.rs", "pub struct Item; pub type Alias = Item;")]);
        let alias = definition(&analyzer, "Alias");
        let target = definition(&analyzer, "Item");
        // Freeze the ordinary request's live declaration identity first.
        // Removing a file before opening a request would change that request's
        // inventory, rather than isolate the alias reader's source dependency.
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.declarations(alias.source()).contains(&alias));
        std::fs::remove_file(alias.source().abs_path()).unwrap();
        assert_eq!(
            brokk_bifrost_rust::hierarchy::canonical_rust_hierarchy_type(
                &analyzer,
                scope.token(),
                alias
            )
            .unwrap(),
            Some(target)
        );
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn canonical_aliases_reject_associated_paths_and_non_reference_wrappers() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub struct Outer<T>(T);
pub struct Item;
pub type Associated = Outer<u8>::Assoc;
pub type Reference = &Item;
pub type Pointer = *const Item;
pub type Array = [Item; 1];
pub type Slice = [Item];
"#,
        )]);

        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "Associated")),
            None,
            "an associated path must not collapse to its nominal outer type"
        );
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "Reference")),
            Some(definition(&analyzer, "Item"))
        );
        for alias in ["Pointer", "Array", "Slice"] {
            assert_eq!(
                canonical_type(&analyzer, definition(&analyzer, alias)),
                None,
                "unsupported wrapper {alias} must not resolve to Item"
            );
        }
    }

    #[test]
    fn canonical_alias_alternatives_agree_only_when_their_targets_agree() {
        let (_fixture, agreeing) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub struct Item;
#[cfg(feature = "one")]
pub type Alias = Item;
#[cfg(not(feature = "one"))]
pub type Alias = Item;
"#,
        )]);
        assert_eq!(
            canonical_type(&agreeing, definition(&agreeing, "Alias")),
            Some(definition(&agreeing, "Item"))
        );

        let (_fixture, disagreeing) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub struct Item;
pub struct Other;
#[cfg(feature = "one")]
pub type Alias = Item;
#[cfg(not(feature = "one"))]
pub type Alias = Other;
"#,
        )]);
        assert_eq!(
            canonical_type(&disagreeing, definition(&disagreeing, "Alias")),
            None,
            "different source alternatives must not certify one target"
        );
    }

    #[test]
    fn embedded_aliases_are_not_promoted_into_the_primary_hierarchy() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub struct Item;
wrap! {
    pub type Hidden = Item;
}
"#,
        )]);

        let file = analyzer.get_analyzed_files().into_iter().next().unwrap();
        let hidden = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "Hidden")
            .expect("embedded alias remains a source declaration");
        assert_eq!(canonical_type(&analyzer, hidden), None);
    }

    #[test]
    fn canonical_aliases_use_the_local_inline_module_import_scope() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "src/lib.rs",
                r#"
mod source;
mod sibling;
mod local {
    use crate::source::Item;
    pub type Alias = Item;
}
mod inline {
    pub struct Item;
    pub type Alias = Item;
}
mod outer {
    pub mod inner {
        pub struct Item;
        pub type Alias = Item;
    }
}
"#,
            ),
            ("src/source.rs", "pub struct Item;"),
            ("src/sibling.rs", "pub struct Item;"),
        ]);

        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "local.Alias")),
            Some(definition(&analyzer, "source.Item"))
        );
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "inline.Alias")),
            Some(definition(&analyzer, "inline.Item"))
        );
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "outer.inner.Alias")),
            Some(definition(&analyzer, "outer.inner.Item"))
        );
    }

    #[test]
    fn canonical_aliases_resolve_structured_qualified_paths() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
mod outer {
    pub struct Item;
    pub mod inner {
        pub struct Item;
        pub type Local = self::Item;
        pub type Parent = super::Item;
        pub type Rooted = crate::outer::Item;
    }
}
mod local {
    use crate::outer;
    pub type Imported = outer::inner::Item;
}
"#,
        )]);
        for (alias, target) in [
            ("outer.inner.Local", "outer.inner.Item"),
            ("outer.inner.Parent", "outer.Item"),
            ("outer.inner.Rooted", "outer.Item"),
            ("local.Imported", "outer.inner.Item"),
        ] {
            assert_eq!(
                canonical_type(&analyzer, definition(&analyzer, alias)),
                Some(definition(&analyzer, target)),
                "{alias}"
            );
        }
    }

    #[test]
    fn canonical_aliases_preserve_ambiguous_inline_import_targets() {
        // The existing export-target boundary retains only file and name,
        // not an inline module identity. Do not claim a unique alias target
        // when that boundary supplies multiple distinct declarations.
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "mod source { pub struct Item; }\nmod sibling { pub struct Item; }\nmod local { use crate::source::Item; pub type Alias = Item; }",
        )]);
        assert_eq!(
            canonical_type(&analyzer, definition(&analyzer, "local.Alias")),
            None
        );
    }

    #[test]
    fn warm_query_indexes_catches_up_the_usage_facts_and_the_hierarchy_still_answers() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Runnable {}
pub struct Worker;
impl Runnable for Worker {}
"#,
        )]);

        assert!(!analyzer.query_indexes_warm());
        assert!(!analyzer.rust_usage_facts_warm());

        analyzer.warm_query_indexes();

        assert!(analyzer.query_indexes_warm());
        assert!(analyzer.rust_usage_facts_warm());

        let runnable = definition(&analyzer, "Runnable");
        let worker = definition(&analyzer, "Worker");
        assert_eq!(analyzer.get_direct_ancestors(&worker), vec![runnable]);
    }

    #[test]
    fn rust_type_relations_record_same_file_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Runnable {}
struct Worker;
impl Runnable for Worker {}
"#,
        )]);

        let runnable = definition(&analyzer, "Runnable");
        let worker = definition(&analyzer, "Worker");

        assert!(has_trait_implementation_relation(
            &analyzer, "Worker", "Runnable"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&worker),
            vec![runnable.clone()]
        );
        assert!(analyzer.get_direct_descendants(&runnable).contains(&worker));
    }

    #[test]
    fn failed_hierarchy_publication_is_not_cached_as_an_empty_family() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "mod contracts;\nuse contracts::Runnable;\npub struct Worker;\nimpl Runnable for Worker { fn run(&self) {} }\n")
            .file("src/contracts.rs", "pub trait Runnable { fn run(&self); }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let member = definition(&analyzer, "contracts.Runnable.run");
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let scope = AnalyzerQueryScope::new(&analyzer);
        let answer = analyzer.member_family(&member, None);
        assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete);
        assert!(scope.store_error().is_some());
    }

    #[test]
    fn blanket_impl_parameter_does_not_resolve_to_same_named_workspace_type() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Marker {
    fn mark(&self) -> u32;
}

pub trait Counted {
    fn count(&self) -> u32;
}

pub struct T;
pub struct Thing;

impl<T: Clone> Marker for T {
    fn mark(&self) -> u32 {
        0
    }
}

impl Counted for Thing {
    fn count(&self) -> u32 {
        1
    }
}
"#,
        )]);

        let marker = definition(&analyzer, "Marker");
        let same_named_type = definition(&analyzer, "T");
        assert!(
            !has_trait_implementation_relation(&analyzer, "T", "Marker"),
            "the impl type parameter shadows the same-named workspace type"
        );
        assert!(
            analyzer.get_direct_ancestors(&same_named_type).is_empty(),
            "the workspace type must not inherit a trait implemented for the blanket parameter"
        );
        assert!(
            !analyzer
                .get_direct_descendants(&marker)
                .contains(&same_named_type),
            "the blanket parameter must not become a concrete trait descendant"
        );

        let counted = definition(&analyzer, "Counted");
        let thing = definition(&analyzer, "Thing");
        assert!(has_trait_implementation_relation(
            &analyzer, "Thing", "Counted"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&thing),
            vec![counted.clone()],
            "a concrete impl in the same file remains indexed"
        );
        assert!(analyzer.get_direct_descendants(&counted).contains(&thing));

        let mark = definition(&analyzer, "Marker.mark");
        let family = analyzer.member_family(&mark, None);
        assert!(
            !family.is_proven(),
            "the blanket impl must still make its trait family unenumerable"
        );
        assert!(family.edges.is_empty());
    }

    /// `declares` is `declarations(file).contains(unit)` without the copy, so
    /// it must give the same answer for every unit a caller can hold: each
    /// declaration asked of its own file and of another file, and each file's
    /// file-scope unit, which `declarations` filters out.
    #[test]
    fn rust_declares_answers_declaration_membership() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/lib.rs", "pub mod worker;\npub trait Runnable {}\n"),
            (
                "src/worker.rs",
                "pub struct Worker;\nimpl crate::Runnable for Worker {}\npub type WorkerAlias = Worker;\n",
            ),
        ]);
        let files = analyzer.analyzed_files();
        let mut units = analyzer.all_declarations().collect::<Vec<_>>();
        assert!(
            units.len() >= 3,
            "the fixture declares a trait, a type and an alias"
        );
        units.extend(files.iter().cloned().map(CodeUnit::file_scope));
        for file in &files {
            let declared = analyzer.declarations(file);
            for unit in &units {
                assert_eq!(
                    analyzer.declares(file, unit),
                    declared.contains(unit),
                    "{file:?} {unit:?}"
                );
            }
        }
    }

    /// Two byte-identical files are one content-addressed blob, so the type
    /// each declares has the same `(blob, source site)` identity. The
    /// trait-implementation rows key each end by its placement as well -- the
    /// file the crate places the declaring module in -- so `one::Runnable` and
    /// `two::Runnable` are two ends, and the readers ask by the `CodeUnit`'s
    /// own file.
    #[test]
    fn rust_hierarchy_keeps_identical_files_distinct() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "src/lib.rs",
                "pub mod one;\npub mod two;\npub mod worker;\n",
            ),
            ("src/one.rs", "pub trait Runnable {}"),
            ("src/two.rs", "pub trait Runnable {}"),
            (
                "src/worker.rs",
                "use crate::one::Runnable;\npub struct Worker;\nimpl Runnable for Worker {}\n",
            ),
        ]);
        let worker = definition(&analyzer, "worker.Worker");
        let ancestors: Vec<String> = analyzer
            .get_direct_ancestors(&worker)
            .iter()
            .map(|unit| unit.fq_name())
            .collect();
        assert_eq!(
            ancestors,
            vec!["one.Runnable".to_string()],
            "the impl names one::Runnable, not both"
        );
        let one = definition(&analyzer, "one.Runnable");
        let two = definition(&analyzer, "two.Runnable");
        assert_eq!(one.source().rel_path(), std::path::Path::new("src/one.rs"));
        assert_eq!(two.source().rel_path(), std::path::Path::new("src/two.rs"));
        assert!(
            analyzer.get_direct_descendants(&one).contains(&worker),
            "one::Runnable is implemented by Worker"
        );
        assert!(
            analyzer.get_direct_descendants(&two).is_empty(),
            "two::Runnable is implemented by nothing: {:?}",
            analyzer.get_direct_descendants(&two)
        );
    }

    #[test]
    fn rust_type_relations_record_imported_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            // The crate root matters here: the per-demand reader answers from
            // the trait-implementation rows, and crate derivation only places
            // a module that some root reaches. A pair of loose files is not a
            // crate, and a file no crate root reaches is not compiled.
            ("src/lib.rs", "pub mod contracts;\npub mod worker;\n"),
            ("src/contracts.rs", "pub trait Runnable {}"),
            (
                "src/worker.rs",
                r#"
use crate::contracts::Runnable;
pub struct Worker;
impl Runnable for Worker {}
"#,
            ),
        ]);

        let runnable = definition(&analyzer, "contracts.Runnable");
        let worker = definition(&analyzer, "worker.Worker");

        assert!(has_trait_implementation_relation(
            &analyzer,
            "worker.Worker",
            "contracts.Runnable"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&worker),
            vec![runnable.clone()]
        );
        assert!(analyzer.get_direct_descendants(&runnable).contains(&worker));
    }
}

#[cfg(test)]
mod member_family_tests {
    use super::tests::{analyzer_with_files, definition, family_edges, member_in_impl};
    use super::*;

    const CONTRACTS: &str = r#"
pub trait Greeter {
    fn greet(&self) -> String;
}

pub trait Shouter {
    fn greet(&self) -> String;
}
"#;

    const PERSON: &str = r#"
use crate::contracts::Greeter;

pub struct Person;

impl Person {
    pub fn greet(&self) -> String {
        String::from("inherent")
    }
}

impl Greeter for Person {
    fn greet(&self) -> String {
        String::from("person")
    }
}
"#;

    const ROBOT: &str = r#"
use crate::contracts::{Greeter, Shouter};

pub struct Robot;

impl Greeter for Robot {
    fn greet(&self) -> String {
        String::from("robot")
    }
}

impl Shouter for Robot {
    fn greet(&self) -> String {
        String::from("shout")
    }
}
"#;

    fn cross_file_workspace() -> (crate::test_support::AnalyzerFixture, RustAnalyzer) {
        analyzer_with_files(&[
            ("src/contracts.rs", CONTRACTS),
            ("src/person.rs", PERSON),
            ("src/robot.rs", ROBOT),
        ])
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn a_trait_method_resolves_to_its_impl_methods_in_other_files() {
        let (_fixture, analyzer) = cross_file_workspace();
        let greet = definition(&analyzer, "contracts.Greeter.greet");

        assert_eq!(
            family_edges(&analyzer, &greet, MethodFamilyRelation::ImplementedBy),
            vec![
                "impl Greeter for Person::fn greet(&self) -> String { ... }".to_string(),
                "impl Greeter for Robot::fn greet(&self) -> String { ... }".to_string(),
            ],
            "a trait method's implementors are the members of every resolved \
             impl of that trait, in whatever file the impl was written"
        );
    }

    #[test]
    fn an_inherent_method_of_the_same_name_is_not_an_implementor() {
        let (_fixture, analyzer) = cross_file_workspace();
        let inherent = member_in_impl(&analyzer, "person.Person.greet", "impl Person::");

        let answer = analyzer.member_family(&inherent, None);
        assert_eq!(
            answer.outcome,
            MemberFamilyOutcome::NoFamily,
            "an inherent method joins no trait family: Rust dispatches it \
             statically, so the complete answer is that it has none"
        );
        assert!(answer.edges.is_empty());

        let greet = definition(&analyzer, "contracts.Greeter.greet");
        let implementors = family_edges(&analyzer, &greet, MethodFamilyRelation::ImplementedBy);
        assert!(
            !implementors
                .iter()
                .any(|edge| edge.contains("impl Person::")),
            "the inherent method must not appear among the trait's \
             implementors, got: {implementors:?}"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn a_different_traits_same_named_method_is_not_an_implementor() {
        let (_fixture, analyzer) = cross_file_workspace();
        let shouter = definition(&analyzer, "contracts.Shouter.greet");

        assert_eq!(
            family_edges(&analyzer, &shouter, MethodFamilyRelation::ImplementedBy),
            vec!["impl Shouter for Robot::fn greet(&self) -> String { ... }".to_string()],
            "`Robot` implements both traits with a same-named method; only the \
             member written in this trait's impl block answers this trait"
        );
    }

    #[test]
    fn an_impl_member_states_the_trait_method_it_implements() {
        let (_fixture, analyzer) = cross_file_workspace();
        let member = member_in_impl(&analyzer, "robot.Robot.greet", "impl Shouter for Robot::");

        let answer = analyzer.member_family(&member, None);
        assert!(answer.is_proven(), "{:?}", answer.reason);
        let forward: Vec<String> = answer
            .edges
            .iter()
            .filter(|edge| edge.relation == MethodFamilyRelation::Implements)
            .map(|edge| format!("{} in {}", edge.target.fq_name(), edge.owner.fq_name()))
            .collect();
        assert_eq!(
            forward,
            vec!["contracts.Shouter.greet in contracts.Shouter".to_string()],
            "the forward edge is the trait method the impl block answers, and \
             it is the same pair the inverse direction was indexed from"
        );
    }

    #[test]
    fn canonical_primary_impls_do_not_bind_generic_parameters_to_workspace_types() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); }
struct T;
impl<T> Contract for T { fn run(&self) {} }
"#,
        )]);
        let concrete = definition(&analyzer, "T");
        assert!(analyzer.get_direct_ancestors(&concrete).is_empty());
        for name in ["Contract.run", "T.run"] {
            let answer = analyzer.member_family(&definition(&analyzer, name), None);
            assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete, "{name}");
            assert!(answer.edges.is_empty());
        }
    }

    #[test]
    fn canonical_primary_impls_preserve_nominal_generic_containers() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); }
struct Wrapper<T>(T);
impl<T> Contract for Wrapper<T> { fn run(&self) {} }
"#,
        )]);
        assert_eq!(
            analyzer.get_direct_ancestors(&definition(&analyzer, "Wrapper")),
            vec![definition(&analyzer, "Contract")]
        );
        let answer = analyzer.member_family(&definition(&analyzer, "Wrapper.run"), None);
        assert!(answer.is_proven(), "{:?}", answer.outcome);
        assert_eq!(answer.edges.len(), 1);
    }

    #[test]
    fn canonical_primary_impls_keep_reference_wrapped_type_parameters_incomplete() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); }
struct T;
impl<'a, T> Contract for &'a T { fn run(&self) {} }
"#,
        )]);
        assert!(
            analyzer
                .get_direct_ancestors(&definition(&analyzer, "T"))
                .is_empty()
        );
        let answer = analyzer.member_family(&definition(&analyzer, "Contract.run"), None);
        assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete);
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn canonical_primary_impls_keep_generic_associated_targets_unresolved() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); }
mod T { pub struct Assoc; }
impl<T> Contract for T::Assoc { fn run(&self) {} }
"#,
        )]);
        assert!(
            analyzer
                .get_direct_ancestors(&definition(&analyzer, "T.Assoc"))
                .is_empty()
        );
        let answer = analyzer.member_family(&definition(&analyzer, "Contract.run"), None);
        assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete);
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn canonical_primary_impls_do_not_turn_negative_impls_into_positive_relations() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract { fn run(&self); } struct Item; impl !Contract for Item {}",
        )]);
        assert!(
            analyzer
                .get_direct_ancestors(&definition(&analyzer, "Item"))
                .is_empty()
        );
        let answer = analyzer.member_family(&definition(&analyzer, "Contract.run"), None);
        assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete);
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn canonical_primary_impls_preserve_ambiguous_member_source_links() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self); }
struct Item;
#[cfg(feature = "first")]
impl Contract for Item { fn run(&self) {} }
#[cfg(not(feature = "first"))]
impl Contract for Item { fn run(&self) {} }
"#,
        )]);
        assert_eq!(
            analyzer.get_direct_ancestors(&definition(&analyzer, "Item")),
            vec![definition(&analyzer, "Contract")]
        );
        for name in ["Contract.run", "Item.run"] {
            let answer = analyzer.member_family(&definition(&analyzer, name), None);
            assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete, "{name}");
            assert!(answer.edges.is_empty());
        }
    }

    #[test]
    fn canonical_primary_impls_keep_malformed_member_evidence_incomplete() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Contract { fn run(&self, value: i32); fn other(&self); }
struct Item;
impl Contract for Item {
    fn run(&self, value: ) {}
    fn other(&self) {}
}
"#,
        )]);
        assert_eq!(
            analyzer.get_direct_ancestors(&definition(&analyzer, "Item")),
            vec![definition(&analyzer, "Contract")],
            "the malformed body does not erase the structurally valid head"
        );
        for name in ["Contract.run", "Item.run", "Item.other"] {
            let answer = analyzer.member_family(&definition(&analyzer, name), None);
            assert_eq!(answer.outcome, MemberFamilyOutcome::Incomplete, "{name}");
            assert!(answer.edges.is_empty());
        }
    }

    #[test]
    fn a_trait_with_a_blanket_impl_answers_unproven() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Marker {
    fn mark(&self) -> u32;
}

pub trait Counted {
    fn count(&self) -> u32;
}

pub struct Thing;

impl<T: Clone> Marker for T {
    fn mark(&self) -> u32 {
        0
    }
}

impl Counted for Thing {
    fn count(&self) -> u32 {
        1
    }
}
"#,
        )]);

        let mark = definition(&analyzer, "Marker.mark");
        let answer = analyzer.member_family(&mark, None);
        assert!(
            !answer.is_proven(),
            "a blanket impl covers types no workspace scan enumerates, so the \
             trait's implementor set cannot be stated"
        );
        assert!(answer.edges.is_empty());

        let count = definition(&analyzer, "Counted.count");
        assert_eq!(
            family_edges(&analyzer, &count, MethodFamilyRelation::ImplementedBy),
            vec!["impl Counted for Thing::fn count(&self) -> u32 { ... }".to_string()],
            "the blanket impl makes its own trait unenumerable, not every trait \
             in the workspace"
        );
    }

    /// A blanket impl has no trait-implementation row and no unresolved-impl
    /// row, so a trait-bounded walk never reads the file it is in unless that
    /// is the trait's own file or a file one of the trait's rows names.
    #[test]
    #[ignore = "finds real bug: a blanket impl outside the trait's own file is invisible to the \
                row-bounded member walk, so the family answers Proven"]
    fn a_blanket_impl_in_another_file_answers_unproven() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/lib.rs", "pub mod marker;\npub mod blanket;\n"),
            (
                "src/marker.rs",
                "pub trait Marker {\n    fn mark(&self) -> u32;\n}\n",
            ),
            (
                "src/blanket.rs",
                "use crate::marker::Marker;\n\
                 impl<T: Clone> Marker for T {\n    fn mark(&self) -> u32 {\n        0\n    }\n}\n",
            ),
        ]);

        let mark = definition(&analyzer, "marker.Marker.mark");
        let answer = analyzer.member_family(&mark, None);
        assert!(
            !answer.is_proven(),
            "a blanket impl outside the trait's file still covers types no \
             workspace scan enumerates"
        );
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn canonical_macro_hierarchy_keeps_raw_direct_item_admission() {
        for invocation in ["generate!", "qualified::generate!", "println!"] {
            let source = format!(
                "trait Contract {{ fn run(&self); }} struct Item;\n\
                 {invocation} {{ impl Contract for Item {{ fn run(&self) {{}} }} }}"
            );
            let (_fixture, analyzer) = analyzer_with_files(&[("src/lib.rs", &source)]);
            let method = definition(&analyzer, "Contract.run");
            let answer = analyzer.member_family(&method, None);
            assert_eq!(
                answer.outcome,
                MemberFamilyOutcome::Incomplete,
                "{invocation}: {answer:?}"
            );
            assert!(
                answer.edges.is_empty(),
                "raw macro impls are uncertainty only"
            );
            assert!(
                analyzer
                    .direct_ancestors(&definition(&analyzer, "Item"))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    /// Replay admits only direct-item invocations, so none of these impls is
    /// ever an edge. The item-level ones are still accounted for: each macro
    /// is visible nowhere, its tokens write the trait's name, and its
    /// expansion could declare an impl of it, so the trait is not enumerable.
    /// A function-local invocation is not at an item position.
    #[test]
    fn canonical_macro_hierarchy_does_not_promote_other_positions_or_nested_replays() {
        for (source, proven) in [
            (
                "trait Contract { fn run(&self); } struct Item;\n\
                 generate!(impl Contract for Item { fn run(&self) {} });",
                false,
            ),
            (
                "trait Contract { fn run(&self); } struct Item;\n\
                 fn local() { generate! { impl Contract for Item { fn run(&self) {} } } }",
                true,
            ),
            (
                "trait Contract { fn run(&self); } struct Item;\n\
                 outer! { inner! { impl Contract for Item { fn run(&self) {} } } }",
                false,
            ),
        ] {
            let (_fixture, analyzer) = analyzer_with_files(&[("src/lib.rs", source)]);
            let method = definition(&analyzer, "Contract.run");
            let answer = analyzer.member_family(&method, None);
            assert_eq!(answer.is_proven(), proven, "{source}: {answer:?}");
            assert!(answer.edges.is_empty());
        }
    }

    /// tract's `element_wise!(..);`: a macro whose body writes an impl of the
    /// trait, invoked at statement position in a file that holds an ordinary
    /// impl of it. Every ordinary impl is a row, and replay does not see the
    /// generated one, so only the invocation says the set is not complete.
    #[test]
    fn a_statement_position_item_macro_beside_an_impl_answers_unproven() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/lib.rs", "#[macro_use]\npub mod ops;\npub mod math;\n"),
            (
                "src/ops.rs",
                r#"
pub trait MiniOp {
    fn name(&self) -> u32;
}

macro_rules! mini_op {
    ($op:ident) => {
        pub struct $op;
        impl $crate::ops::MiniOp for $op {
            fn name(&self) -> u32 {
                0
            }
        }
    };
}
"#,
            ),
            (
                "src/math.rs",
                r#"
use crate::ops::MiniOp;

pub struct Real;

impl MiniOp for Real {
    fn name(&self) -> u32 {
        1
    }
}

mini_op!(Abs);
"#,
            ),
        ]);

        let name = definition(&analyzer, "ops.MiniOp.name");
        let answer = analyzer.member_family(&name, None);
        assert!(!answer.is_proven(), "{answer:?}");
        assert!(answer.edges.is_empty());
        let member = member_in_impl(&analyzer, "math.Real.name", "impl MiniOp for Real");
        assert!(!analyzer.member_family(&member, None).is_proven());
    }

    /// Bifrost's `impl_forward_query_provider!(XAnalyzer);`: the macro's rules
    /// write the impl, and it is invoked, qualified, from files that never
    /// write the trait's name. The defining file writes it inside the
    /// macro's token tree, which is what brings the invoking files into the
    /// walk, in either delimiter form.
    #[test]
    fn a_macro_invoked_where_the_trait_is_never_named_answers_unproven() {
        for invocation in ["crate::mini_op!(Abs);", "crate::mini_op! { Abs }"] {
            let (_fixture, analyzer) = analyzer_with_files(&[
                ("src/lib.rs", "pub mod ops;\npub mod generated;\n"),
                (
                    "src/ops.rs",
                    r#"
pub trait MiniOp {
    fn name(&self) -> u32;
}

#[macro_export]
macro_rules! mini_op {
    ($op:ident) => {
        pub struct $op;
        impl $crate::ops::MiniOp for $op {
            fn name(&self) -> u32 {
                0
            }
        }
    };
}
"#,
                ),
                ("src/generated.rs", invocation),
            ]);
            let name = definition(&analyzer, "ops.MiniOp.name");
            let answer = analyzer.member_family(&name, None);
            assert!(!answer.is_proven(), "{invocation}: {answer:?}");
            assert!(answer.edges.is_empty());
        }
    }

    /// A file joins the walk because some token tree in it writes the trait's
    /// name. An item macro whose own input does not write it, and whose macro
    /// is not one that brought the file here, cannot name the trait.
    #[test]
    fn only_an_item_macro_whose_input_names_the_trait_counts() {
        for (item_macro, proven) in [
            ("other!(pub struct Unrelated;);", true),
            ("other!(pub struct Unrelated; MiniOp);", false),
        ] {
            let math = format!(
                "use crate::ops::MiniOp;\n\
                 pub struct Real;\n\
                 impl MiniOp for Real {{ fn name(&self) -> u32 {{ 1 }} }}\n\
                 pub fn size() -> usize {{ std::convert::identity(format!(\"{{}}\", 1).len()) + \
                 vec![0usize; std::mem::size_of::<&dyn MiniOp>()].len() }}\n\
                 {item_macro}\n"
            );
            let (_fixture, analyzer) = analyzer_with_files(&[
                ("src/lib.rs", "pub mod ops;\npub mod math;\n"),
                (
                    "src/ops.rs",
                    "pub trait MiniOp {\n    fn name(&self) -> u32;\n}\n",
                ),
                ("src/math.rs", &math),
            ]);
            let name = definition(&analyzer, "ops.MiniOp.name");
            let answer = analyzer.member_family(&name, None);
            assert_eq!(answer.is_proven(), proven, "{item_macro}: {answer:?}");
        }
    }

    /// A file joins the walk because it writes a macro's name, and that is
    /// all it says about that one macro: an unqualified invocation of another
    /// macro there cannot be it. A qualified invocation's macro has no
    /// recorded name, so it could be.
    #[test]
    fn an_invoking_file_counts_only_invocations_that_could_be_the_macro() {
        for (other, proven) in [("other!(Abs);", true), ("crate::other!(Abs);", false)] {
            let tool = format!("pub fn mini_op() {{}}\n{other}\n");
            let (_fixture, analyzer) = analyzer_with_files(&[
                ("src/lib.rs", "pub mod ops;\npub mod math;\npub mod tool;\n"),
                (
                    "src/ops.rs",
                    r#"
pub trait MiniOp {
    fn name(&self) -> u32;
}

#[macro_export]
macro_rules! mini_op {
    ($op:ident) => {
        impl $crate::ops::MiniOp for $op {
            fn name(&self) -> u32 {
                0
            }
        }
    };
}
"#,
                ),
                (
                    "src/math.rs",
                    "use crate::ops::MiniOp;\n\
                     pub struct Real;\n\
                     impl MiniOp for Real { fn name(&self) -> u32 { 1 } }\n",
                ),
                ("src/tool.rs", &tool),
            ]);
            let name = definition(&analyzer, "ops.MiniOp.name");
            let answer = analyzer.member_family(&name, None);
            assert_eq!(answer.is_proven(), proven, "{other}: {answer:?}");
        }
    }

    /// A decorating passthrough replays its arguments under its `cfg`. When
    /// no crate that places the file activates that `cfg`, an impl among the
    /// arguments is not compiled and says nothing about the family; when one
    /// does, it is uncertainty as any replayed impl is.
    #[test]
    fn a_statement_position_passthrough_under_an_inactive_cfg_adds_no_impl() {
        for (decoration, proven) in [("any()", true), ("all()", false)] {
            let lib = format!(
                "macro_rules! keep {{ ($($item:item)*) => {{ $( #[cfg({decoration})] $item )* }}; }}\n\
                 pub mod ops;\npub mod math;\n"
            );
            let (_fixture, analyzer) = analyzer_with_files(&[
                (
                    "Cargo.toml",
                    "[package]\nname = \"keep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                ("src/lib.rs", &lib),
                (
                    "src/ops.rs",
                    "pub trait MiniOp {\n    fn name(&self) -> u32;\n}\n",
                ),
                (
                    "src/math.rs",
                    "use crate::ops::MiniOp;\n\
                     pub struct Real;\n\
                     impl MiniOp for Real { fn name(&self) -> u32 { 1 } }\n\
                     pub struct Other;\n\
                     keep!(impl MiniOp for Other { fn name(&self) -> u32 { 2 } });\n",
                ),
            ]);
            let name = definition(&analyzer, "keep.ops.MiniOp.name");
            let answer = analyzer.member_family(&name, None);
            assert_eq!(answer.is_proven(), proven, "cfg({decoration}): {answer:?}");
            if proven {
                assert_eq!(
                    family_edges(&analyzer, &name, MethodFamilyRelation::ImplementedBy),
                    vec!["impl MiniOp for Real::fn name(&self) -> u32 { ... }".to_string()],
                );
            }
        }
    }

    /// A statement-position passthrough whose rules expand to their arguments
    /// and nothing else adds no item, so it leaves the family enumerable even
    /// where its arguments write the trait's name; an impl among its arguments
    /// is uncertainty, never an edge.
    #[test]
    fn a_statement_position_passthrough_adds_nothing_beyond_its_arguments() {
        for (arguments, proven) in [
            (
                "pub struct Other; pub fn other() -> Option<&'static dyn MiniOp> { None }",
                true,
            ),
            (
                "pub struct Other; impl MiniOp for Other { fn name(&self) -> u32 { 2 } }",
                false,
            ),
        ] {
            let math = format!(
                "use crate::ops::MiniOp;\n\
                 pub struct Real;\n\
                 impl MiniOp for Real {{ fn name(&self) -> u32 {{ 1 }} }}\n\
                 keep!({arguments});\n"
            );
            // A manifest, so that `math.rs` is placed only as the module the
            // macro is visible in and not also as a crate root of its own.
            let (_fixture, analyzer) = analyzer_with_files(&[
                (
                    "Cargo.toml",
                    "[package]\nname = \"keep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "src/lib.rs",
                    "macro_rules! keep { ($($item:item)*) => { $($item)* }; }\n\
                     pub mod ops;\npub mod math;\n",
                ),
                (
                    "src/ops.rs",
                    "pub trait MiniOp {\n    fn name(&self) -> u32;\n}\n",
                ),
                ("src/math.rs", &math),
            ]);
            let name = definition(&analyzer, "keep.ops.MiniOp.name");
            let answer = analyzer.member_family(&name, None);
            assert_eq!(answer.is_proven(), proven, "{arguments}: {answer:?}");
            if proven {
                assert_eq!(
                    family_edges(&analyzer, &name, MethodFamilyRelation::ImplementedBy),
                    vec!["impl MiniOp for Real::fn name(&self) -> u32 { ... }".to_string()],
                );
            } else {
                assert!(answer.edges.is_empty());
            }
        }
    }

    #[test]
    fn canonical_macro_hierarchy_retains_primary_import_scope() {
        // `generate!` expands to its arguments and nothing else, so its
        // replayed interior is all it adds, and only where that interior's
        // impl resolves decides which trait loses enumerability.
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/a.rs", "pub trait Contract { fn run(&self); }"),
            ("src/b.rs", "pub trait Contract { fn run(&self); }"),
            (
                "src/lib.rs",
                "macro_rules! generate { ($($item:item)*) => { $($item)* }; }\n\
                 mod a; mod b; use crate::a::Contract; struct Item;\n\
                 generate! { use crate::b::Contract; impl Contract for Item { fn run(&self) {} } }",
            ),
        ]);
        let primary = analyzer.member_family(&definition(&analyzer, "a.Contract.run"), None);
        let embedded = analyzer.member_family(&definition(&analyzer, "b.Contract.run"), None);
        assert_eq!(
            primary.outcome,
            MemberFamilyOutcome::Incomplete,
            "{primary:?}"
        );
        assert!(embedded.is_proven(), "{embedded:?}");
    }

    #[test]
    fn canonical_macro_hierarchy_does_not_reopen_source_in_frozen_query() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            "trait Contract { fn run(&self); } struct Item;\n\
             impl Contract for Item { fn run(&self) {} }\n\
             generate! { impl Contract for Other { fn run(&self) {} } }",
        )]);
        let trait_unit = definition(&analyzer, "Contract");
        let target = definition(&analyzer, "Item");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.declarations(target.source()).contains(&target));
        std::fs::remove_file(target.source().abs_path()).unwrap();
        let files: Vec<_> = analyzer.get_analyzed_files().into_iter().collect();
        let index = brokk_bifrost_rust::hierarchy::RustHierarchyIndex::read_over(
            &analyzer,
            scope.token(),
            &files,
        )
        .unwrap();
        assert_eq!(index.direct_ancestors.get(&target), Some(&vec![trait_unit]));
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn a_trait_impl_inside_a_macro_makes_that_trait_unproven() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Marker {
    fn mark(&self) -> u32;
}

pub struct Thing;

impl Marker for Thing {
    fn mark(&self) -> u32 {
        1
    }
}

generate! {
    pub struct Other;

    impl Marker for Other {
        fn mark(&self) -> u32 {
            2
        }
    }
}
"#,
        )]);

        let mark = definition(&analyzer, "Marker.mark");
        let answer = analyzer.member_family(&mark, None);
        assert!(
            !answer.is_proven(),
            "the declaration walk indexes items inside a macro token tree, so a \
             trait implemented there has an implementor this pass cannot read; \
             the family must not claim to be exhaustive"
        );
    }

    #[test]
    fn a_malformed_trait_sibling_makes_a_known_method_unenumerable() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Contract {
    fn known(&self);
    fn malformed(&self, value: );
}

pub struct Item;

impl Contract for Item {
    fn known(&self) {}
}
"#,
        )]);

        let known = definition(&analyzer, "Contract.known");
        let answer = analyzer.member_family(&known, None);
        assert_eq!(
            answer.outcome,
            MemberFamilyOutcome::Incomplete,
            "a malformed sibling means the known method's trait table is not complete: {:?}",
            answer.reason
        );
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn a_direct_macro_in_a_primary_trait_makes_members_unenumerable() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Contract {
    fn known(&self);
    generated!();
}

pub struct Item;

impl Contract for Item {
    fn known(&self) {}
}
"#,
        )]);

        let known = definition(&analyzer, "Contract.known");
        let answer = analyzer.member_family(&known, None);
        assert_eq!(
            answer.outcome,
            MemberFamilyOutcome::Incomplete,
            "a direct trait-body macro can add unknown members: {:?}",
            answer.reason
        );
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn an_embedded_trait_is_not_promoted_into_the_primary_method_table() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Primary {
    fn known(&self);
}

pub struct Item;

impl Primary for Item {
    fn known(&self) {}
}

wrap! {
    pub trait Embedded {
        fn hidden(&self);
    }
}
"#,
        )]);

        let file = analyzer.get_analyzed_files().into_iter().next().unwrap();
        let hidden = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "hidden")
            .expect("embedded trait method remains a source declaration");
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(matches!(
            brokk_bifrost_rust::hierarchy::rust_member_family_of(&analyzer, scope.token(), &hidden)
                .expect("published fixture hierarchy"),
            brokk_bifrost_rust::hierarchy::RustMemberFamily::NotTracked
        ));
    }

    #[test]
    fn alternative_trait_declarations_do_not_certify_a_combined_method_table() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
#[cfg(feature = "one")]
pub trait Contract { fn known(&self); }
#[cfg(not(feature = "one"))]
pub trait Contract { fn known(&self); fn other(&self); }
pub struct Item;
impl Contract for Item { fn known(&self) {} }
"#,
        )]);
        let known = definition(&analyzer, "Contract.known");
        let answer = analyzer.member_family(&known, None);
        assert_eq!(
            answer.outcome,
            MemberFamilyOutcome::Incomplete,
            "distinct source alternatives must not become one proven table: {:?}",
            answer.reason
        );
        assert!(answer.edges.is_empty());
        let implementation = member_in_impl(&analyzer, "Item.known", "impl Contract for Item::");
        let answer = analyzer.member_family(&implementation, None);
        assert_eq!(
            answer.outcome,
            MemberFamilyOutcome::Incomplete,
            "the corresponding impl member also has an uncertain family: {:?}",
            answer.reason
        );
        assert!(answer.edges.is_empty());
    }

    /// A trait named through a re-exporting glob, the way tract names `Op`
    /// through `use crate::internal::*`, is bound by crate derivation, which
    /// follows the glob and the re-export; the header walk does not. The
    /// member family takes such an impl from its crate row, so the trait's
    /// family and the impl member's own family are both stated.
    #[test]
    fn an_impl_named_through_a_reexporting_glob_is_taken_from_its_row() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "src/lib.rs",
                "pub mod ops;\npub mod internal {\n    pub use crate::ops::*;\n}\npub mod gather;\n",
            ),
            (
                "src/ops.rs",
                "pub trait Op {\n    fn name(&self) -> u32;\n}\n",
            ),
            (
                "src/gather.rs",
                r#"
use crate::internal::*;

pub struct Gather;

impl Op for Gather {
    fn name(&self) -> u32 {
        1
    }
}
"#,
            ),
        ]);
        let name = definition(&analyzer, "ops.Op.name");
        assert_eq!(
            family_edges(&analyzer, &name, MethodFamilyRelation::ImplementedBy),
            vec!["impl Op for Gather::fn name(&self) -> u32 { ... }".to_string()],
        );
        let member = member_in_impl(&analyzer, "gather.Gather.name", "impl Op for Gather");
        let answer = analyzer.member_family(&member, None);
        assert!(
            answer.is_proven(),
            "{:?} ({:?})",
            answer.outcome,
            answer.reason
        );
        let implements: Vec<_> = answer
            .edges
            .iter()
            .filter(|edge| edge.relation == MethodFamilyRelation::Implements)
            .map(|edge| edge.target.fq_name().to_string())
            .collect();
        assert_eq!(implements, ["ops.Op.name"]);
    }

    /// A member walk resolves only the impl headers spelled the way the
    /// trait's rows spell it, so a trait implemented under an imported rename
    /// and under its own name keeps both implementors, and an impl of another
    /// trait in the same file is not one of them.
    #[test]
    fn a_trait_implemented_under_a_renamed_import_keeps_that_implementor() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "src/lib.rs",
                "pub mod contracts;\npub mod person;\npub mod robot;\n",
            ),
            ("src/contracts.rs", CONTRACTS),
            (
                "src/person.rs",
                r#"
use crate::contracts::Greeter as Hello;
use crate::contracts::Shouter;

pub struct Person;

impl Hello for Person {
    fn greet(&self) -> String {
        String::from("person")
    }
}

impl Shouter for Person {
    fn greet(&self) -> String {
        String::from("loud")
    }
}
"#,
            ),
            (
                "src/robot.rs",
                r#"
use crate::contracts::Greeter;

pub struct Robot;

impl Greeter for Robot {
    fn greet(&self) -> String {
        String::from("robot")
    }
}
"#,
            ),
        ]);
        let greet = definition(&analyzer, "contracts.Greeter.greet");
        assert_eq!(
            family_edges(&analyzer, &greet, MethodFamilyRelation::ImplementedBy),
            vec![
                "impl Greeter for Robot::fn greet(&self) -> String { ... }".to_string(),
                "impl Hello for Person::fn greet(&self) -> String { ... }".to_string(),
            ],
        );
    }

    /// An impl written in a module that does not declare its self type gives
    /// its members a parent that has no declaration in their file: the self
    /// type is declared in `ruby/mod.rs` and reaches `ruby/imports.rs` through
    /// `use super::*`, and the impl names its trait by a qualified path. That
    /// parent is not a trait, so the member's family is the impl's trait's,
    /// read over the trait's own files like any other.
    #[test]
    fn an_impl_outside_the_self_types_module_has_the_traits_family() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/lib.rs", "pub mod contracts;\npub mod ruby;\n"),
            (
                "src/contracts.rs",
                "pub trait Source {\n    fn all_files(&self) -> u32;\n    fn other(&self) -> u32;\n}\n",
            ),
            (
                "src/ruby/mod.rs",
                "mod imports;\npub struct RubyAnalyzer;\n",
            ),
            (
                "src/ruby/imports.rs",
                r#"
use super::*;

impl crate::contracts::Source for RubyAnalyzer {
    fn all_files(&self) -> u32 {
        1
    }
    fn other(&self) -> u32 {
        2
    }
}
"#,
            ),
        ]);
        let imports = analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with("imports.rs"))
            .expect("imports.rs is analyzed");
        let declared = analyzer.declarations(&imports);
        let member = declared
            .iter()
            .find(|unit| unit.identifier() == "all_files")
            .unwrap_or_else(|| panic!("imports.rs declares all_files: {declared:?}"))
            .clone();
        let answer = analyzer.member_family(&member, None);
        assert!(
            answer.is_proven(),
            "{} (parent {:?}): {:?} ({:?})",
            member.fq_name(),
            analyzer.parent_of(&member),
            answer.outcome,
            answer.reason
        );
        let implements: Vec<_> = answer
            .edges
            .iter()
            .filter(|edge| edge.relation == MethodFamilyRelation::Implements)
            .map(|edge| edge.target.fq_name().to_string())
            .collect();
        assert_eq!(implements, ["contracts.Source.all_files"]);
    }

    #[test]
    fn a_trait_with_no_implementations_has_a_complete_empty_family() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
pub trait Unused {
    fn run(&self) -> u32;
}
"#,
        )]);

        let run = definition(&analyzer, "Unused.run");
        assert_eq!(
            family_edges(&analyzer, &run, MethodFamilyRelation::ImplementedBy),
            Vec::<String>::new(),
            "no implementor in the workspace is a complete answer, not an \
             unproven one"
        );
    }
}

/// Trait impls whose trait is written with a crate-qualified path, or imported
/// from another crate of the same Cargo workspace (issue #2775).
#[cfg(test)]
mod cross_crate_tests {
    use super::tests::{analyzer_with_files, definition};
    use super::*;
    use crate::analyzer::type_relations::TypeRelationKind;

    /// The whole workspace's hierarchy facts, for fixtures that assert about
    /// the relation itself rather than about one question's answer.
    ///
    /// Production never reads the workspace this way any more: every question
    /// is answered from the rows and a bounded file set. These fixtures are
    /// small enough that reading every file is the clearest way to state what
    /// they are checking.
    fn workspace_hierarchy(
        analyzer: &RustAnalyzer,
    ) -> brokk_bifrost_rust::hierarchy::RustHierarchyIndex {
        let scope = AnalyzerQueryScope::new(analyzer);
        let files: Vec<_> = analyzer.get_analyzed_files().into_iter().collect();
        brokk_bifrost_rust::hierarchy::RustHierarchyIndex::read_over(
            analyzer,
            scope.token(),
            &files,
        )
        .expect("published fixture hierarchy")
    }

    fn implements(analyzer: &RustAnalyzer, from: &str, to: &str) -> bool {
        workspace_hierarchy(analyzer)
            .relations
            .iter()
            .any(|relation| {
                relation.from.fq_name() == from
                    && relation.to.fq_name() == to
                    && relation.kind == TypeRelationKind::TraitImplementation
            })
    }

    const CORE_MANIFEST: &str =
        "[package]\nname = \"core-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
    const CORE_LIB: &str = "pub mod tool;\n";
    const CORE_TOOL: &str = r#"
pub trait Tool {
    fn name(&self) -> String;
}
"#;

    /// The direct shape: a sibling workspace member names the trait through
    /// the declaring crate's own name.
    #[test]
    fn a_sibling_workspace_crates_trait_resolves_through_its_own_crate_name() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/core\", \"app\"]\nresolver = \"2\"\n",
            ),
            ("crates/core/Cargo.toml", CORE_MANIFEST),
            ("crates/core/src/lib.rs", CORE_LIB),
            ("crates/core/src/tool.rs", CORE_TOOL),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore-crate = { path = \"../crates/core\" }\n",
            ),
            (
                "app/src/lib.rs",
                r#"
use core_crate::tool::Tool;

pub struct Add;

impl Tool for Add {
    fn name(&self) -> String {
        String::from("add")
    }
}
"#,
            ),
        ]);

        assert!(
            implements(&analyzer, "app.Add", "core_crate.tool.Tool"),
            "relations: {:?}",
            workspace_hierarchy(&analyzer).relations
        );
    }

    /// The rig shape: the trait is reached through a facade crate that
    /// glob-re-exports the crate that declares it, so `facade::tool` names a
    /// module of neither crate's physical layout.
    #[test]
    fn a_trait_re_exported_by_a_facade_crate_resolves_through_the_facade_path() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "Cargo.toml",
                "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\nmembers = [\"crates/core\", \"app\"]\nresolver = \"2\"\n\n[dependencies]\ncore-crate = { path = \"crates/core\" }\n",
            ),
            ("src/lib.rs", "pub use core_crate::*;\n"),
            ("crates/core/Cargo.toml", CORE_MANIFEST),
            ("crates/core/src/lib.rs", CORE_LIB),
            ("crates/core/src/tool.rs", CORE_TOOL),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfacade = { path = \"..\" }\n",
            ),
            (
                "app/src/lib.rs",
                r#"
use facade::tool::Tool;

pub struct Add;

impl Tool for Add {
    fn name(&self) -> String {
        String::from("add")
    }
}
"#,
            ),
        ]);

        assert!(
            implements(&analyzer, "app.Add", "core_crate.tool.Tool"),
            "relations: {:?}",
            workspace_hierarchy(&analyzer).relations
        );
        let name = definition(&analyzer, "core_crate.tool.Tool.name");
        let answer = analyzer.member_family(&name, None);
        assert!(answer.is_proven(), "{:?}", answer.reason);
    }

    /// A crate that is not a workspace member stays unresolved: naming a
    /// trait `other::tool::Tool` must not be answered by a same-named
    /// workspace trait.
    #[test]
    fn a_trait_path_into_a_crate_outside_the_workspace_stays_unresolved() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/core\", \"app\"]\nresolver = \"2\"\n",
            ),
            ("crates/core/Cargo.toml", CORE_MANIFEST),
            ("crates/core/src/lib.rs", CORE_LIB),
            ("crates/core/src/tool.rs", CORE_TOOL),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfar-away = \"1\"\n",
            ),
            (
                "app/src/lib.rs",
                r#"
use far_away::tool::Tool;

pub struct Add;

impl Tool for Add {
    fn name(&self) -> String {
        String::from("add")
    }
}
"#,
            ),
        ]);

        assert!(
            !implements(&analyzer, "app.Add", "core_crate.tool.Tool"),
            "a registry crate outside the workspace is a real external \
             boundary; a same-named workspace trait must not answer for it"
        );
    }
}

/// Trait impls written inside an inline module that glob-imports the module
/// around it -- the `#[cfg(test)] mod tests { use super::*; }` layout (#2775).
#[cfg(test)]
mod inline_module_tests {
    use super::tests::{analyzer_with_files, definition, family_edges};
    use super::*;

    /// One unresolved impl inside `mod tests` is enough to make the trait
    /// unenumerable, so the trait's whole family stays unproven until the
    /// inline module's `use super::*` resolves against the module the impl is
    /// actually written in.
    #[test]
    fn an_impl_in_an_inline_module_resolves_the_trait_its_parent_declares() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/tool.rs",
            r#"
pub trait Tool {
    fn name(&self) -> String;
}

pub struct Adder;

impl Tool for Adder {
    fn name(&self) -> String {
        String::from("adder")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct Probe;

    impl Tool for Probe {
        fn name(&self) -> String {
            String::from("probe")
        }
    }
}
"#,
        )]);

        let name = definition(&analyzer, "tool.Tool.name");
        assert_eq!(
            family_edges(&analyzer, &name, MethodFamilyRelation::ImplementedBy),
            vec![
                "impl Tool for Adder::fn name(&self) -> String { ... }".to_string(),
                "impl Tool for Probe::fn name(&self) -> String { ... }".to_string(),
            ],
            "the impl inside `mod tests` names the same trait as the one \
             beside it, so both are members of one proven family"
        );
    }

    /// A local declaration shadows the glob import, so the nearer name still
    /// wins and the glob route never turns one answer into an ambiguity.
    #[test]
    fn a_declaration_in_the_inline_module_shadows_the_glob_imported_one() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/tool.rs",
            r#"
pub trait Tool {
    fn name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    pub trait Tool {
        fn name(&self) -> String;
    }

    pub struct Probe;

    impl Tool for Probe {
        fn name(&self) -> String {
            String::from("probe")
        }
    }
}
"#,
        )]);

        let outer = definition(&analyzer, "tool.Tool.name");
        assert_eq!(
            family_edges(&analyzer, &outer, MethodFamilyRelation::ImplementedBy),
            Vec::<String>::new(),
            "the inline module declares its own `Tool`, which shadows the \
             glob-imported one; the outer trait has no implementor"
        );
        let inner = definition(&analyzer, "tool.tests.Tool.name");
        assert_eq!(
            family_edges(&analyzer, &inner, MethodFamilyRelation::ImplementedBy),
            vec!["impl Tool for Probe::fn name(&self) -> String { ... }".to_string()],
        );
    }
}
