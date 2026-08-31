//! The analyzer-owned half of Rust's type hierarchy: the `TypeHierarchyProvider`
//! and `MemberFamilyProvider` capability impls and the `OnceLock` cells behind
//! them.
//!
//! The index itself and every predicate it is built from live in
//! [`brokk_bifrost_rust::hierarchy`] and [`brokk_bifrost_rust::graph_support`].

use crate::analyzer::common::language_for_file;
use crate::analyzer::structural::resolution::{
    MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason, MethodFamilyRelation,
};
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::usages::{MemberFamilyAnswer, MemberFamilyEdge, MemberFamilyProvider};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{CodeUnit, CodeUnitIndex, Language, TypeHierarchyProvider};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_rust::graph_support::{
    is_rust_enum_declaration, is_rust_struct_declaration, is_rust_trait_declaration,
    is_rust_trait_impl_member_declaration, is_rust_type_alias_declaration,
};
use brokk_bifrost_rust::hierarchy::{RustHierarchyIndex, RustMemberFamily, RustMemberFamilyEdge};

use super::RustAnalyzer;

impl TypeHierarchyProvider for RustAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || is_rust_trait_declaration(self, code_unit) {
            return Vec::new();
        }

        self.hierarchy_index()
            .direct_ancestors
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || !is_rust_trait_declaration(self, code_unit) {
            return HashSet::default();
        }

        self.hierarchy_index()
            .direct_descendants
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        is_rust_trait_declaration(self, code_unit)
            || is_rust_struct_declaration(self, code_unit)
            || is_rust_enum_declaration(self, code_unit)
            || is_rust_type_alias_declaration(self, code_unit)
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
        return MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod);
    }

    let (implements, implemented_by) = match analyzer.hierarchy_index().member_family(member) {
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
            let owner_is_trait = analyzer
                .parent_of(member)
                .is_some_and(|parent| is_rust_trait_declaration(analyzer, &parent));
            return if owner_is_trait || is_rust_trait_impl_member_declaration(analyzer, member) {
                MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::OwnerUnknown)
            } else {
                MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod)
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
    pub fn hierarchy_index(&self) -> &RustHierarchyIndex {
        self.hierarchy_index
            .get_or_init(|| RustHierarchyIndex::build(self, AnalyzerQueryScope::new(self).token()))
    }

    pub fn type_relations(&self) -> &[TypeRelation] {
        self.type_relations
            .get_or_init(|| self.hierarchy_index().relations.clone())
            .as_slice()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::type_relations::TypeRelationKind;
    use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language};
    use crate::test_support::AnalyzerFixture;

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

    fn has_trait_implementation_relation(analyzer: &RustAnalyzer, from: &str, to: &str) -> bool {
        analyzer.type_relations().iter().any(|relation| {
            relation.from.fq_name() == from
                && relation.to.fq_name() == to
                && relation.kind == TypeRelationKind::TraitImplementation
        })
    }

    #[test]
    fn warm_query_indexes_builds_the_hierarchy_and_catches_up_the_usage_facts() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Runnable {}
pub struct Worker;
impl Runnable for Worker {}
"#,
        )]);

        assert!(!analyzer.query_indexes_warm());
        assert!(analyzer.hierarchy_index.get().is_none());
        assert!(!analyzer.rust_usage_facts_warm());

        analyzer.warm_query_indexes();

        assert!(analyzer.query_indexes_warm());
        assert!(analyzer.hierarchy_index.get().is_some());
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

    #[test]
    fn rust_type_relations_record_imported_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[
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

    fn implements(analyzer: &RustAnalyzer, from: &str, to: &str) -> bool {
        analyzer.type_relations().iter().any(|relation| {
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
            analyzer.type_relations()
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
            analyzer.type_relations()
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
