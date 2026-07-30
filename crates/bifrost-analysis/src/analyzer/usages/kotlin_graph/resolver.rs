//! What a Kotlin usage query is looking for, and how a spelled name becomes a
//! declaration while looking for it.
//!
//! Two things live here. [`TargetSpec`] is the question — which declaration are
//! we finding references to — derived once per query and read by every scan.
//! [`KotlinNameResolver`] is the answer side: it turns a name as *spelled* in
//! Kotlin source into the fully-qualified name it denotes at a given position,
//! through Kotlin's real precedence ladder.
//!
//! The ladder itself is not reimplemented here. `crate::analyzer::kotlin::types`
//! owns it as `resolve_kotlin_type_name`, parameterised over a "does this
//! fully-qualified name exist" predicate. This module supplies a predicate backed
//! by `IAnalyzer::global_usage_definition_index`, which under `MultiAnalyzer`
//! merges the declarations of every language in the workspace. That is what lets
//! a Kotlin file resolve a Java type declared next door, and it is why the
//! predicate is not `KotlinAnalyzer::source_type_exists`: the Kotlin-only lookup
//! would silently drop every cross-language answer.

use crate::analyzer::kotlin::declarations::kotlin_package_name;
use crate::analyzer::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};
use crate::analyzer::{CodeUnit, IAnalyzer, ImportInfo, ProjectFile, Range};
use std::cell::RefCell;

/// How many levels of ancestor scope a name lookup inherits.
///
/// Matches `MAX_INHERITED_SCOPE_DEPTH` in `crate::analyzer::kotlin::types` and
/// the same constant in the #1238 definition resolver, so navigation and usages
/// see the same scope for the same position.
const MAX_INHERITED_SCOPE_DEPTH: usize = 4;

/// What kind of declaration a query is finding references to.
///
/// Kotlin properties are one kind rather than two: `declarations.rs` indexes a
/// property as a single `Field` unit even when it declares a custom `get()`/
/// `set()`, so `obj.value` and `obj.value = 1` name the same declaration and
/// modelling accessors separately would invent identities the index does not
/// have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TargetKind {
    Type,
    Constructor,
    Function,
    Property,
}

pub(super) struct TargetSpec {
    /// The declaration the query names.
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    /// The declaration that owns `target`; the target itself when it is a type.
    ///
    /// For a type query this is what a reference must resolve to. For the
    /// callable and property kinds milestone 2 adds, it is the type a receiver
    /// must have.
    pub(super) owner: CodeUnit,
}

impl TargetSpec {
    pub(super) fn from_targets(analyzer: &dyn IAnalyzer, targets: &[CodeUnit]) -> Option<Self> {
        // Kotlin overloads collapse into one indexed identity: two functions
        // with the same fully-qualified name become a single `CodeUnit` carrying
        // several signatures. So the overload set a caller passes describes one
        // declaration, and the first entry is enough to identify it. Milestone 2
        // reads the arities off that identity, which is where the several
        // signatures start to matter.
        Self::from_target(analyzer, targets.first()?)
    }

    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() || is_kotlin_type_alias(analyzer, target) {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Property
        } else if target.identifier() == owner.identifier() {
            // Kotlin constructors are indexed as synthetic `Owner.Owner`
            // callables, so sharing the owner's spelling is what identifies one.
            TargetKind::Constructor
        } else {
            TargetKind::Function
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner,
        })
    }
}

/// Whether `unit` is a Kotlin `typealias`.
///
/// `declarations.rs` indexes a type alias as a `Field` `CodeUnit` and records the
/// alias-ness separately, so `is_class()` is false for one. That makes the flag
/// load-bearing here twice over: an alias is *referenced* in type positions
/// (`val v: Parent`), so a query for one is a type query, and a spelled name can
/// *resolve* to one, so the name ladder has to count it as an existing type.
/// Without this, a query for an alias would fall into the property arm and be
/// answered by receiver typing, which an alias never has.
fn is_kotlin_type_alias(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_field()
        && analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(unit))
}

/// The file-level half of a Kotlin name scope: what the file declares itself to
/// be in, and what it imported.
struct KotlinFileFacts {
    package_name: String,
    imports: Vec<ImportInfo>,
}

/// Turns spelled Kotlin names into fully-qualified names, for one file scan.
///
/// Holds the per-file facts the ladder needs and caches the enclosing-scope
/// lookup, which is otherwise repeated for every reference in the file.
pub(super) struct KotlinNameResolver<'a> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    facts: KotlinFileFacts,
    /// Scope owners by the byte offset asked about. A file scan asks this once
    /// per reference and the answer only changes when the enclosing declaration
    /// changes, so without the cache a large file re-walks the owner chain
    /// hundreds of times.
    owners_at: RefCell<Vec<(usize, Vec<String>)>>,
}

impl<'a> KotlinNameResolver<'a> {
    pub(super) fn new(
        analyzer: &'a dyn IAnalyzer,
        file: &'a ProjectFile,
        root: tree_sitter::Node<'_>,
        source: &str,
    ) -> Self {
        Self {
            analyzer,
            file,
            facts: KotlinFileFacts {
                // Read from the syntax tree rather than from an indexed
                // declaration: a file whose declarations were dropped by parse
                // recovery still has a package header, and the same-package tier
                // of the ladder needs it.
                package_name: kotlin_package_name(root, source),
                imports: analyzer
                    .import_analysis_provider()
                    .map(|provider| provider.import_info_of(file))
                    .unwrap_or_default(),
            },
            owners_at: RefCell::new(Vec::new()),
        }
    }

    /// The fully-qualified name the type `spelled` at `byte` denotes.
    ///
    /// Answers with the *name*, not a declaration, because in the JVM realm the
    /// name is the identity. Two source files declaring `lib.Base` — a vendored
    /// copy, or the same package built by two modules — are one classpath entry
    /// and therefore one usage-graph node, so a reference to `Base` is a
    /// reference to both. Returning a single `CodeUnit` here would have to either
    /// pick one arbitrarily or fail closed, and failing closed would report zero
    /// usages for every duplicated type in a monorepo. Java's usage graph reports
    /// both copies for exactly this reason.
    pub(super) fn resolve_type_fqn(&self, spelled: &str, byte: usize) -> Option<String> {
        self.resolve_type_name(spelled, byte).resolved()
    }

    pub(super) fn resolve_type_name(&self, spelled: &str, byte: usize) -> KotlinTypeName {
        let owners = self.scope_owners_at(byte);
        let scope = KotlinNameScope {
            package_name: &self.facts.package_name,
            imports: &self.facts.imports,
            scope_owners: owners,
        };
        resolve_kotlin_type_name(spelled, &scope, |candidate| self.type_exists(candidate))
    }

    /// Whether any language in the workspace indexes a type named `fqn`.
    ///
    /// Kotlin type aliases count: a spelled name can resolve to one, and a
    /// reference through an alias is a reference to the alias. Synthetic units do
    /// not: Kotlin's primary constructors are synthetic `Owner.Owner` callables,
    /// and no type reference names one.
    fn type_exists(&self, fqn: &str) -> bool {
        self.analyzer
            .global_usage_definition_index()
            .by_fqn(fqn)
            .iter()
            .any(|unit| {
                !unit.is_synthetic()
                    && unit.fq_name() == fqn
                    && (unit.is_class() || is_kotlin_type_alias(self.analyzer, unit))
            })
    }

    /// Fully-qualified names of the declarations enclosing `byte`, innermost
    /// first, plus the scopes they inherit.
    fn scope_owners_at(&self, byte: usize) -> Vec<String> {
        if let Some((_, owners)) = self
            .owners_at
            .borrow()
            .iter()
            .find(|(cached, _)| *cached == byte)
        {
            return owners.clone();
        }
        let owners = self.compute_scope_owners_at(byte);
        self.owners_at.borrow_mut().push((byte, owners.clone()));
        owners
    }

    fn compute_scope_owners_at(&self, byte: usize) -> Vec<String> {
        let Some(enclosing) = self.analyzer.enclosing_code_unit(
            self.file,
            &Range {
                start_byte: byte,
                end_byte: byte.saturating_add(1),
                start_line: 0,
                end_line: 0,
            },
        ) else {
            return Vec::new();
        };
        let mut owners = Vec::new();
        let mut lexical = Vec::new();
        let mut current = Some(enclosing);
        while let Some(unit) = current {
            let fqn = unit.fq_name();
            if !owners.contains(&fqn) {
                owners.push(fqn.clone());
                lexical.push(unit.clone());
            }
            current = self.analyzer.parent_of(&unit);
        }

        // A class can name a type its superclass declares, so what the lexical
        // owners inherit is part of the scope too. Depth-capped because a cyclic
        // or malformed hierarchy would otherwise make one name lookup unbounded.
        let Some(provider) = self.analyzer.type_hierarchy_provider() else {
            return owners;
        };
        let mut frontier = lexical;
        for _ in 0..MAX_INHERITED_SCOPE_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                for ancestor in provider.get_direct_ancestors(unit) {
                    let fqn = ancestor.fq_name();
                    if !owners.contains(&fqn) {
                        owners.push(fqn);
                        next.push(ancestor);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        owners
    }
}
