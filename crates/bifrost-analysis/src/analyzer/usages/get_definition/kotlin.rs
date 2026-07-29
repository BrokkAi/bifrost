//! Kotlin definition navigation (issue #1238).
//!
//! Answers "the token at this location refers to which declaration?" for
//! Kotlin source. Every fact comes from the pinned Kotlin tree-sitter syntax
//! tree (`crates/bifrost-analysis/vendor/tree-sitter-kotlin`) or from the
//! analyzer's indexed declarations; nothing is recovered by scanning source
//! text.
//!
//! # What the grammar gives us
//!
//! The vendored Kotlin grammar is field-poor: only `function_declaration` and
//! `property_declaration` carry a `receiver` field, so "the callee of this
//! call" and "the member of this navigation" are read positionally from named
//! children rather than by field name. The shapes this module matches:
//!
//! - a call is `call_expression` = callee expression, then `call_suffix`
//!   (holding `value_arguments` and/or a trailing `annotated_lambda`);
//! - a member access is `navigation_expression` = receiver expression, then
//!   `navigation_suffix` whose named child is the member `simple_identifier`
//!   (`.` and `?.` produce the same shape; `!!` wraps the receiver in
//!   `postfix_expression`);
//! - a type reference is `user_type`, whose `type_identifier` children are the
//!   dotted segments (`lib.Base` is one `user_type` with two children);
//! - an import is `import_header` = `identifier` (one `simple_identifier` per
//!   segment), optional `import_alias`, optional `wildcard_import`.
//!
//! # How a name becomes a declaration
//!
//! Name precedence is not reimplemented here. `crate::analyzer::kotlin::types`
//! owns Kotlin's ladder (enclosing scopes, then explicit imports, then the
//! file's package, then star imports, then default imports) as
//! [`resolve_kotlin_type_name`], parameterised over a "does this
//! fully-qualified name exist" predicate. This module supplies a predicate
//! backed by [`BoundedDefinitionLookup`], which is realm-aware: in a mixed
//! Java/Kotlin/Scala workspace a Kotlin file resolves a Java type declared next
//! door. Calling `KotlinAnalyzer::resolve_type_name_in_file` instead would
//! bypass `MultiAnalyzer`'s realm widening and silently lose those answers.

use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::kotlin::declarations::kotlin_package_name;
use crate::analyzer::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};
use crate::analyzer::tree_walk::{first_named_child_of_kind, named_children};

/// How many levels of ancestor scope a name lookup inherits.
///
/// Matches `MAX_INHERITED_SCOPE_DEPTH` in `crate::analyzer::kotlin::types`:
/// inherited nested types are rare and deep chains rarer, and a small cap keeps
/// a cyclic hierarchy from turning one lookup into an unbounded traversal.
const MAX_INHERITED_SCOPE_DEPTH: usize = 4;

pub(super) fn parse_kotlin_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
        .ok()?;
    parser.parse(source.as_bytes(), None)
}

pub(crate) fn resolve_kotlin(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("kotlin_parse_failed", "Kotlin source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Kotlin definition",
                site.text
            ),
        );
    };

    let ctx = KotlinCtx::new(analyzer, support, file, source, root);

    if let Some(header) = kotlin_enclosing_import_header(node) {
        return kotlin_import_reference_outcome(&ctx, header, node);
    }
    if kotlin_is_declaration_name(node) {
        return no_definition(
            "declaration_site",
            format!(
                "`{}` is a Kotlin declaration name, not a reference",
                site.text
            ),
        );
    }

    match node.kind() {
        "type_identifier" => kotlin_type_reference_outcome(&ctx, node),
        kind => no_definition(
            "unsupported_kotlin_reference_shape",
            format!(
                "`{}` is a Kotlin `{kind}` reference shape that get_definition does not resolve yet",
                site.text
            ),
        ),
    }
}

/// Everything a Kotlin resolver step needs about the request it is serving.
///
/// The package name and imports are read once per request: both are file-wide
/// facts, and every name lookup in the request consults them.
struct KotlinCtx<'a> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    source: &'a str,
    package_name: String,
    imports: Vec<ImportInfo>,
}

impl<'a> KotlinCtx<'a> {
    fn new(
        analyzer: &'a dyn IAnalyzer,
        support: &'a dyn BoundedDefinitionLookup,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'_>,
    ) -> Self {
        // The package comes from the syntax tree rather than from an indexed
        // declaration: a file whose only content is a reference, or whose
        // declarations were dropped by parse recovery, still has a package
        // header, and the same-package tier of the ladder needs it.
        let package_name = kotlin_package_name(root, source);
        let imports = analyzer
            .import_analysis_provider()
            .map(|provider| provider.import_info_of(file))
            .unwrap_or_default();
        Self {
            analyzer,
            support,
            file,
            source,
            package_name,
            imports,
        }
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or_default()
    }

    /// The names visible at `byte`: the file's package and imports, plus the
    /// enclosing declarations and the scopes they inherit.
    fn scope_at(&self, byte: usize) -> KotlinNameScope<'_> {
        KotlinNameScope {
            package_name: &self.package_name,
            imports: &self.imports,
            scope_owners: self.scope_owners_at(byte),
        }
    }

    /// Resolve a spelled Kotlin name to the fully-qualified name it denotes.
    fn resolve_name(&self, spelled: &str, scope: &KotlinNameScope<'_>) -> KotlinTypeName {
        resolve_kotlin_type_name(spelled, scope, |candidate| self.type_exists(candidate))
    }

    fn types_named(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| unit.is_class() && !unit.is_synthetic())
            .collect()
    }

    fn type_exists(&self, fqn: &str) -> bool {
        !self.types_named(fqn).is_empty()
    }

    /// The declarations enclosing `byte`, innermost first, followed by the
    /// scopes they inherit.
    ///
    /// A Kotlin class can name its own nested types unqualified, and the nested
    /// types its supertypes declare, so both belong in the scope tier of the
    /// ladder. Ancestors are expanded through the analyzer's hierarchy
    /// provider, which is realm-aware: a Kotlin class extending a Java class in
    /// the same workspace inherits that class's scope too.
    fn scope_owners_at(&self, byte: usize) -> Vec<String> {
        let Some(start) = self.analyzer.enclosing_code_unit(
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

        let mut lexical = Vec::new();
        let mut current = Some(start);
        while let Some(unit) = current {
            current = self.analyzer.parent_of(&unit);
            lexical.push(unit);
        }

        let mut owners: Vec<String> = Vec::new();
        for unit in &lexical {
            let fqn = unit.fq_name();
            if !owners.contains(&fqn) {
                owners.push(fqn);
            }
        }

        let Some(provider) = self.analyzer.type_hierarchy_provider() else {
            return owners;
        };
        let mut frontier = lexical;
        for _ in 0..MAX_INHERITED_SCOPE_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                for ancestor in provider.get_direct_ancestors(unit) {
                    let fqn = ancestor.fq_name();
                    if owners.contains(&fqn) {
                        continue;
                    }
                    owners.push(fqn);
                    next.push(ancestor);
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

/// The `import_header` `node` sits inside, if any.
///
/// Walking up rather than testing the parent alone: an import's focus can land
/// on the `identifier`'s `simple_identifier`, on the `import_alias`'s
/// `type_identifier`, or on the header itself.
fn kotlin_enclosing_import_header(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "import_header" {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

/// Whether `node` is the name a declaration introduces rather than a reference
/// to something declared elsewhere.
fn kotlin_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let expected_kind = match parent.kind() {
        "class_declaration" | "object_declaration" | "companion_object" | "type_alias"
        | "type_parameter" => "type_identifier",
        "function_declaration"
        | "variable_declaration"
        | "parameter"
        | "class_parameter"
        | "enum_entry"
        | "parameter_with_optional_type" => "simple_identifier",
        _ => return false,
    };
    node.kind() == expected_kind
        && first_named_child_of_kind(parent, expected_kind)
            .is_some_and(|name| name.id() == node.id())
}

/// Resolve a focus inside `import a.b.C`, `import a.b.C as D`, or `import a.b.*`.
///
/// Focusing segment *k* of the dotted path means the prefix `0..=k`: putting
/// the cursor on `b` in `import a.b.C` asks about `a.b`, not about `a.b.C`.
/// Focusing the alias asks about the whole path, which is what makes an aliased
/// import navigable from its local name.
fn kotlin_import_reference_outcome(
    ctx: &KotlinCtx<'_>,
    header: Node<'_>,
    focus: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(path) = first_named_child_of_kind(header, "identifier") else {
        return no_definition(
            "no_reference_text",
            "Kotlin import has no qualified path to resolve",
        );
    };
    let segments = named_children(path)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return no_definition(
            "no_reference_text",
            "Kotlin import has no qualified path to resolve",
        );
    }

    // A focus on a path segment asks about the prefix ending there; anything
    // else in the header (the alias, the star, the header itself) asks about
    // the whole path.
    let last = segments
        .iter()
        .position(|segment| segment.id() == focus.id())
        .unwrap_or(segments.len() - 1);
    let candidate = segments[..=last]
        .iter()
        .map(|segment| ctx.text(*segment))
        .collect::<Vec<_>>()
        .join(".");

    let mut units = ctx
        .support
        .fqn_in_any_language(&candidate)
        .into_iter()
        .filter(|unit| !unit.is_synthetic())
        .collect::<Vec<_>>();
    if !units.is_empty() {
        sort_units(&mut units);
        units.dedup();
        return candidates_outcome(units);
    }
    if ctx.support.package_exists_in_any_language(&candidate) {
        return no_definition(
            "package_reference",
            format!("`{candidate}` names a package, which has no declaration to navigate to"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{candidate}` is not indexed as a Kotlin definition"),
    )
}

/// Resolve a focus on a `type_identifier`: a type annotation, a supertype, an
/// annotation name, a receiver type, or a type argument.
fn kotlin_type_reference_outcome(ctx: &KotlinCtx<'_>, node: Node<'_>) -> DefinitionLookupOutcome {
    let spelled = kotlin_type_spelling_through(ctx, node);
    if spelled.is_empty() {
        return no_definition("no_reference_text", "Kotlin type reference is blank");
    }
    let scope = ctx.scope_at(node.start_byte());
    match ctx.resolve_name(&spelled, &scope) {
        KotlinTypeName::Resolved(fqn) => {
            let units = ctx.types_named(&fqn);
            if units.is_empty() {
                return no_definition(
                    "no_indexed_definition",
                    format!("`{fqn}` resolved as a Kotlin type but has no indexed definition"),
                );
            }
            candidates_outcome(units)
        }
        KotlinTypeName::Ambiguous => no_definition(
            "ambiguous_kotlin_type",
            format!("`{spelled}` is bound to different owners by more than one Kotlin star import"),
        ),
        KotlinTypeName::Unresolved => {
            if ctx.support.package_exists_in_any_language(&spelled) {
                return no_definition(
                    "package_reference",
                    format!("`{spelled}` names a package, which has no declaration to navigate to"),
                );
            }
            no_definition(
                "no_indexed_definition",
                format!("`{spelled}` is not indexed as a Kotlin type"),
            )
        }
    }
}

/// The dotted name a focused `type_identifier` spells, up to and including
/// itself.
///
/// A dotted type is one `user_type` node with one `type_identifier` child per
/// segment, so focusing `Outer` in `Outer.Inner` asks about `Outer` while
/// focusing `Inner` asks about `Outer.Inner`. Joining the children's own text
/// is a structural read of the tree, not a re-parse of the source.
fn kotlin_type_spelling_through(ctx: &KotlinCtx<'_>, node: Node<'_>) -> String {
    let Some(parent) = node.parent().filter(|parent| parent.kind() == "user_type") else {
        return ctx.text(node).to_string();
    };
    let segments = named_children(parent)
        .into_iter()
        .filter(|child| child.kind() == "type_identifier")
        .collect::<Vec<_>>();
    let last = segments
        .iter()
        .position(|segment| segment.id() == node.id())
        .unwrap_or(segments.len().saturating_sub(1));
    segments[..=last]
        .iter()
        .map(|segment| ctx.text(*segment))
        .collect::<Vec<_>>()
        .join(".")
}
