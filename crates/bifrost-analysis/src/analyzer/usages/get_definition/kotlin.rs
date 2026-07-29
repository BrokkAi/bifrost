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
use std::cell::RefCell;
use std::rc::Rc;

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
        "simple_identifier" => kotlin_identifier_reference_outcome(&ctx, node),
        kind => no_definition(
            "unsupported_kotlin_reference_shape",
            format!(
                "`{}` is a Kotlin `{kind}` reference shape that get_definition does not resolve yet",
                site.text
            ),
        ),
    }
}

/// Route a focused `simple_identifier` to the resolver for the shape it sits in.
///
/// `simple_identifier` is Kotlin's most overloaded node: it spells callees,
/// members, named-argument labels, and bare value references alike. The parent
/// node is what distinguishes them.
fn kotlin_identifier_reference_outcome(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = ctx.text(node);
    if name.is_empty() {
        return no_definition("no_reference_text", "Kotlin reference is blank");
    }
    let Some(parent) = node.parent() else {
        return kotlin_bare_value_outcome(ctx, node, name);
    };

    if parent.kind() == "value_argument" && kotlin_named_argument_label(parent, node) {
        return kotlin_named_argument_outcome(ctx, parent, name);
    }
    if let Some(call) = kotlin_call_with_callee(node) {
        return kotlin_bare_call_outcome(ctx, node, name, Some(kotlin_call_arity(call)));
    }
    if parent.kind() == "callable_reference" {
        // `::topLevel` names a callable without applying it, so no arity is
        // proven and every overload of the name is a legitimate answer.
        return kotlin_bare_call_outcome(ctx, node, name, None);
    }
    if parent.kind() == "navigation_suffix" {
        return kotlin_member_outcome(ctx, parent, name);
    }
    kotlin_bare_value_outcome(ctx, node, name)
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
    /// Parsed syntax of the files this request has had to look inside, keyed by
    /// file. Resolving a reference regularly needs a fact that lives in another
    /// file's *syntax* rather than in its index — whether a nested object is a
    /// `companion_object`, what a parameter is called, what type a property
    /// declares — and re-reading and re-parsing the same file for each of those
    /// questions would be quadratic in a chained expression.
    file_syntax: RefCell<HashMap<ProjectFile, Option<Rc<KotlinFileSyntax>>>>,
    /// Package name and imports per file. A declaration's own file decides what
    /// its spelled types mean, so resolving the return type of a function in
    /// another file needs *that* file's scope, not the requesting file's.
    file_facts: RefCell<HashMap<ProjectFile, Rc<KotlinFileFacts>>>,
}

/// The file-level half of a Kotlin name scope.
struct KotlinFileFacts {
    package_name: String,
    imports: Vec<ImportInfo>,
}

/// A complete Kotlin name scope, owned so it can be built for any file.
///
/// [`KotlinNameScope`] borrows its file-level parts, which a per-file cache
/// cannot hand out; this owns them and lends a `KotlinNameScope` on demand.
struct KotlinScope {
    facts: Rc<KotlinFileFacts>,
    owners: Vec<String>,
}

impl KotlinScope {
    fn as_name_scope(&self) -> KotlinNameScope<'_> {
        KotlinNameScope {
            package_name: &self.facts.package_name,
            imports: &self.facts.imports,
            scope_owners: self.owners.clone(),
        }
    }
}

/// One file's source together with its parse, owned so a caller can hold nodes
/// borrowed from the tree for as long as it holds the `Rc`.
struct KotlinFileSyntax {
    source: String,
    tree: Tree,
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
        let facts = Rc::new(KotlinFileFacts {
            package_name: kotlin_package_name(root, source),
            imports: analyzer
                .import_analysis_provider()
                .map(|provider| provider.import_info_of(file))
                .unwrap_or_default(),
        });
        let mut file_facts = HashMap::default();
        file_facts.insert(file.clone(), facts);
        Self {
            analyzer,
            support,
            file,
            source,
            file_syntax: RefCell::new(HashMap::default()),
            file_facts: RefCell::new(file_facts),
        }
    }

    /// The package and imports of `file`.
    fn file_facts(&self, file: &ProjectFile) -> Rc<KotlinFileFacts> {
        if let Some(cached) = self.file_facts.borrow().get(file) {
            return Rc::clone(cached);
        }
        let package_name = self
            .file_syntax(file)
            .map(|syntax| kotlin_package_name(syntax.tree.root_node(), &syntax.source))
            .unwrap_or_default();
        let facts = Rc::new(KotlinFileFacts {
            package_name,
            imports: self
                .analyzer
                .import_analysis_provider()
                .map(|provider| provider.import_info_of(file))
                .unwrap_or_default(),
        });
        self.file_facts
            .borrow_mut()
            .insert(file.clone(), Rc::clone(&facts));
        facts
    }

    /// The parsed syntax of `file`, read from the analyzer's indexed content so
    /// the answer matches the generation the declaration ranges came from.
    fn file_syntax(&self, file: &ProjectFile) -> Option<Rc<KotlinFileSyntax>> {
        if let Some(cached) = self.file_syntax.borrow().get(file) {
            return cached.clone();
        }
        let syntax = self
            .analyzer
            .indexed_source(file)
            .or_else(|| self.analyzer.project().read_source(file).ok())
            .and_then(|source| {
                let tree = parse_kotlin_tree(&source)?;
                Some(Rc::new(KotlinFileSyntax { source, tree }))
            });
        self.file_syntax
            .borrow_mut()
            .insert(file.clone(), syntax.clone());
        syntax
    }

    /// The syntax node a declaration was indexed from.
    ///
    /// Declaration ranges are recorded against the file's own bytes, so the
    /// smallest named node covering the range is the declaration itself. This
    /// is how a resolver asks a *structural* question about a declaration in
    /// another file — is this object a companion, what is this parameter
    /// called, what type does this property declare — without inventing a
    /// second, text-based model of Kotlin.
    fn declaration_syntax(&self, unit: &CodeUnit) -> Option<(Rc<KotlinFileSyntax>, Range)> {
        let range = self.analyzer.ranges(unit).into_iter().min()?;
        let syntax = self.file_syntax(unit.source())?;
        Some((syntax, range))
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or_default()
    }

    /// The names visible at `byte` of the requesting file.
    fn scope_at(&self, byte: usize) -> KotlinScope {
        self.scope_in(self.file, byte)
    }

    /// The names visible at `byte` of `file`: that file's package and imports,
    /// plus the declarations enclosing the position and the scopes they inherit.
    fn scope_in(&self, file: &ProjectFile, byte: usize) -> KotlinScope {
        KotlinScope {
            facts: self.file_facts(file),
            owners: self.scope_owners_at(file, byte),
        }
    }

    /// Resolve a spelled Kotlin name to the fully-qualified name it denotes.
    fn resolve_name(&self, spelled: &str, scope: &KotlinScope) -> KotlinTypeName {
        resolve_kotlin_type_name(spelled, &scope.as_name_scope(), |candidate| {
            self.type_exists(candidate)
        })
    }

    /// The type declaration a spelled name denotes in `scope`, if exactly one
    /// indexed declaration answers to it.
    fn resolve_type_unit(&self, spelled: &str, scope: &KotlinScope) -> Option<CodeUnit> {
        let fqn = self.resolve_name(spelled, scope).resolved()?;
        let mut units = self.types_named(&fqn);
        (units.len() == 1).then(|| units.remove(0))
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

    /// Ordinary callables declared at `fqn`.
    ///
    /// Synthetic units are excluded: Kotlin's constructors are synthetic
    /// `Owner.Owner` callables, and a call spelled without a receiver reaches
    /// them through the type tier, never by looking up a function of that name.
    fn callables_named(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| unit.is_function() && !unit.is_synthetic())
            .collect()
    }

    /// Declarations at `fqn` that a bare name can denote as a value: a
    /// property, an enum entry, an object, or a class used as a qualifier.
    fn values_named(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| {
                !unit.is_synthetic() && (unit.is_field() || unit.is_class() || unit.is_function())
            })
            .collect()
    }

    /// Whether `unit`'s recorded arity admits a call passing `arity` arguments.
    ///
    /// A callable with no recorded arity is treated as accepting the call:
    /// missing metadata is an absence of evidence, and using it to reject a
    /// candidate would turn a gap in indexing into a confident wrong answer.
    fn accepts_arity(&self, unit: &CodeUnit, arity: usize) -> bool {
        let metadata = self.analyzer.signature_metadata(unit);
        if metadata.is_empty() {
            return true;
        }
        metadata.iter().any(|entry| {
            entry
                .callable_arity()
                .is_none_or(|callable| callable.accepts(arity))
        })
    }

    /// Whether `unit` declares a parameter spelled `label`.
    ///
    /// The parameter's name is read from the declaring file's syntax at the byte
    /// range the indexer recorded for it, so a parameter written
    /// `vararg names: List<String> = emptyList()` yields `names` structurally
    /// rather than by picking the label apart.
    fn declares_parameter(&self, unit: &CodeUnit, label: &str) -> bool {
        let Some(syntax) = self.file_syntax(unit.source()) else {
            return false;
        };
        self.analyzer
            .signature_metadata(unit)
            .iter()
            .flat_map(|entry| entry.parameters().to_vec())
            .any(|parameter| {
                kotlin_declaration_node(
                    syntax.tree.root_node(),
                    &Range {
                        start_byte: parameter.start_byte(),
                        end_byte: parameter.end_byte(),
                        start_line: 0,
                        end_line: 0,
                    },
                )
                .and_then(|node| first_named_child_of_kind(node, "simple_identifier"))
                .and_then(|name| name.utf8_text(syntax.source.as_bytes()).ok())
                .is_some_and(|name| name == label)
            })
    }

    /// The companion objects declared directly inside `owner_fqn`.
    ///
    /// Kotlin lets a class's own body, and its subclasses, name companion
    /// members without qualification, so a companion is a scope in its own
    /// right. Companion-ness is read from the declaration's syntax
    /// (`companion_object` versus `object_declaration`) because the two are
    /// indistinguishable in the index: both are nested classes.
    fn companion_fqns(&self, owner_fqn: &str) -> Vec<String> {
        self.support
            .fqn_direct_children(owner_fqn)
            .into_iter()
            .filter(|unit| unit.is_class() && self.is_companion_object(unit))
            .map(|unit| unit.fq_name())
            .collect()
    }

    /// Members declared at `fqn` that can answer a reference, optionally
    /// restricted to those that accept a call of `arity`.
    fn members_named(&self, fqn: &str, arity: Option<usize>) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| !unit.is_synthetic() && (unit.is_function() || unit.is_field()))
            .filter(|unit| {
                arity.is_none_or(|arity| !unit.is_function() || self.accepts_arity(unit, arity))
            })
            .collect()
    }

    /// The innermost class-like declaration enclosing `byte` in the requesting
    /// file.
    fn enclosing_class_at(&self, byte: usize) -> Option<CodeUnit> {
        let start = self.analyzer.enclosing_code_unit(
            self.file,
            &Range {
                start_byte: byte,
                end_byte: byte.saturating_add(1),
                start_line: 0,
                end_line: 0,
            },
        )?;
        let mut current = Some(start);
        while let Some(unit) = current {
            if unit.is_class() {
                return Some(unit);
            }
            current = self.analyzer.parent_of(&unit);
        }
        None
    }

    /// The type a declaration carries: a property's or parameter's written
    /// type, an enum entry's own enum, or a function's declared return type.
    ///
    /// Read from the declaring file's syntax and resolved in *that* file's
    /// scope, because a spelled type means whatever the file that wrote it says
    /// it means.
    fn declared_type_of(&self, unit: &CodeUnit, depth: usize) -> Option<CodeUnit> {
        let (syntax, range) = self.declaration_syntax(unit)?;
        let node = kotlin_declaration_node(syntax.tree.root_node(), &range)?;
        // An enum entry has no written type: it is an instance of its own enum.
        if node.kind() == "enum_entry" {
            return self.analyzer.parent_of(unit).filter(CodeUnit::is_class);
        }

        let declaring = KotlinCtx {
            analyzer: self.analyzer,
            support: self.support,
            file: unit.source(),
            source: &syntax.source,
            file_syntax: RefCell::new(HashMap::default()),
            file_facts: RefCell::new(HashMap::default()),
        };
        let type_node = match node.kind() {
            "property_declaration" => named_children(node)
                .into_iter()
                .find(|child| child.kind() == "variable_declaration")
                .and_then(|variable| {
                    named_children(variable)
                        .into_iter()
                        .find_map(|child| kotlin_type_node_spelling(&declaring, child))
                }),
            "function_declaration" => kotlin_declared_return_type_spelling(&declaring, node),
            _ => named_children(node)
                .into_iter()
                .find_map(|child| kotlin_type_node_spelling(&declaring, child)),
        };
        if let Some(spelled) = type_node {
            let scope = declaring.scope_in(unit.source(), range.start_byte);
            if let Some(resolved) = declaring.resolve_type_unit(&spelled, &scope) {
                return Some(resolved);
            }
        }
        if node.kind() != "property_declaration" {
            return None;
        }
        // A property with no written type is only typed when its initializer
        // proves one.
        let initializer = named_children(node)
            .into_iter()
            .rev()
            .find(|child| kotlin_is_expression_kind(child.kind()))?;
        kotlin_expression_type(&declaring, initializer, depth + 1)
    }

    /// The type an extension function extends, or `None` when the callable is
    /// not an extension.
    fn extension_receiver_unit(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        let (syntax, range) = self.declaration_syntax(unit)?;
        let node = kotlin_declaration_node(syntax.tree.root_node(), &range)?;
        let receiver = node.child_by_field_name("receiver")?;
        let declaring = KotlinCtx {
            analyzer: self.analyzer,
            support: self.support,
            file: unit.source(),
            source: &syntax.source,
            file_syntax: RefCell::new(HashMap::default()),
            file_facts: RefCell::new(HashMap::default()),
        };
        let spelled = kotlin_type_node_spelling(&declaring, receiver)?;
        let scope = declaring.scope_in(unit.source(), range.start_byte);
        declaring.resolve_type_unit(&spelled, &scope)
    }

    /// Whether `subtype` is `supertype` or inherits from it.
    fn type_conforms_to(&self, subtype: &CodeUnit, supertype: &CodeUnit) -> bool {
        if subtype.fq_name() == supertype.fq_name() {
            return true;
        }
        let Some(provider) = self.analyzer.type_hierarchy_provider() else {
            return false;
        };
        let target = supertype.fq_name();
        let mut seen = Vec::new();
        let mut frontier = vec![subtype.clone()];
        for _ in 0..MAX_MEMBER_HIERARCHY_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                for ancestor in provider.get_direct_ancestors(unit) {
                    let fqn = ancestor.fq_name();
                    if fqn == target {
                        return true;
                    }
                    if seen.contains(&fqn) {
                        continue;
                    }
                    seen.push(fqn);
                    next.push(ancestor);
                }
            }
            if next.is_empty() {
                return false;
            }
            frontier = next;
        }
        false
    }

    fn is_companion_object(&self, unit: &CodeUnit) -> bool {
        let Some((syntax, range)) = self.declaration_syntax(unit) else {
            return false;
        };
        kotlin_declaration_node(syntax.tree.root_node(), &range)
            .is_some_and(|node| node.kind() == "companion_object")
    }

    /// The declarations enclosing `byte`, innermost first, followed by the
    /// scopes they inherit.
    ///
    /// A Kotlin class can name its own nested types unqualified, and the nested
    /// types its supertypes declare, so both belong in the scope tier of the
    /// ladder. Ancestors are expanded through the analyzer's hierarchy
    /// provider, which is realm-aware: a Kotlin class extending a Java class in
    /// the same workspace inherits that class's scope too.
    fn scope_owners_at(&self, file: &ProjectFile, byte: usize) -> Vec<String> {
        let Some(start) = self.analyzer.enclosing_code_unit(
            file,
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
            if owners.contains(&fqn) {
                continue;
            }
            owners.extend(self.companion_fqns(&fqn));
            owners.push(fqn);
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
                    owners.extend(self.companion_fqns(&fqn));
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

// ---------------------------------------------------------------------------
// Calls, constructors, and named arguments.
// ---------------------------------------------------------------------------

/// The `call_expression` whose callee is `node`, if any.
///
/// A call's children are the callee expression followed by `call_suffix`, so
/// "is this the callee" is "is this the first named child that is not the
/// suffix" — the grammar exposes no field to ask directly.
fn kotlin_call_with_callee(node: Node<'_>) -> Option<Node<'_>> {
    let call = node
        .parent()
        .filter(|parent| parent.kind() == "call_expression")?;
    (kotlin_callee(call)?.id() == node.id()).then_some(call)
}

fn kotlin_callee(call: Node<'_>) -> Option<Node<'_>> {
    named_children(call)
        .into_iter()
        .find(|child| child.kind() != "call_suffix")
}

/// How many arguments a call passes.
///
/// A trailing lambda (`items.forEach { … }`) is an argument even though it sits
/// outside the parentheses, so it counts: without it, every trailing-lambda
/// call would look like it passed one argument too few and would fail to match
/// its own overload.
fn kotlin_call_arity(call: Node<'_>) -> usize {
    let Some(suffix) = first_named_child_of_kind(call, "call_suffix") else {
        return 0;
    };
    let positional = first_named_child_of_kind(suffix, "value_arguments")
        .map(|arguments| {
            named_children(arguments)
                .into_iter()
                .filter(|child| child.kind() == "value_argument")
                .count()
        })
        .unwrap_or(0);
    let trailing = usize::from(first_named_child_of_kind(suffix, "annotated_lambda").is_some());
    positional + trailing
}

/// Whether `node` is the *label* of a named argument rather than its value.
///
/// `foo(name = 1)` is `(value_argument (simple_identifier) (integer_literal))`;
/// a positional `foo(name)` is `(value_argument (simple_identifier))`. The label
/// is therefore the first of two or more named children.
fn kotlin_named_argument_label(argument: Node<'_>, node: Node<'_>) -> bool {
    let children = named_children(argument);
    children.len() > 1 && children[0].id() == node.id()
}

/// Resolve `name(...)` where `name` is spelled without a receiver.
///
/// Functions are tried before constructors because a Kotlin function may share
/// a class's spelling, and a call that matches a function is a call of that
/// function. Both tiers run through the same precedence ladder, so an import
/// shadows a same-package declaration for callables exactly as it does for
/// types.
///
/// Arity participates in the ladder rather than filtering its result. Kotlin
/// picks the overload that can accept the call even when a nearer scope
/// declares the same name with a different shape: inside a subclass that
/// declares `run(Int)`, the call `run(1) { … }` means the inherited
/// `run(Int, () -> Unit)`. Filtering afterwards could not express that, because
/// the ladder would already have stopped at the nearer scope. When no scope has
/// a callable that accepts the call, the ladder runs again ignoring arity: an
/// arity mismatch means the recorded metadata is incomplete, not that the
/// declaration does not exist.
fn kotlin_bare_call_outcome(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    name: &str,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let scope = ctx.scope_at(node.start_byte());
    for required_arity in [arity, None] {
        match resolve_kotlin_type_name(name, &scope.as_name_scope(), |candidate| {
            ctx.callables_named(candidate)
                .iter()
                .any(|unit| required_arity.is_none_or(|arity| ctx.accepts_arity(unit, arity)))
        }) {
            KotlinTypeName::Resolved(fqn) => {
                return kotlin_callable_outcome(ctx.callables_named(&fqn), &fqn);
            }
            KotlinTypeName::Ambiguous => {
                return no_definition(
                    "ambiguous_kotlin_type",
                    format!(
                        "`{name}` is bound to different owners by more than one Kotlin star import"
                    ),
                );
            }
            KotlinTypeName::Unresolved => {}
        }
        if required_arity.is_none() {
            break;
        }
    }

    match ctx.resolve_name(name, &scope) {
        KotlinTypeName::Resolved(type_fqn) => kotlin_constructor_outcome(ctx, &type_fqn),
        KotlinTypeName::Ambiguous => no_definition(
            "ambiguous_kotlin_type",
            format!("`{name}` is bound to different owners by more than one Kotlin star import"),
        ),
        KotlinTypeName::Unresolved => no_definition(
            "no_indexed_definition",
            format!("`{name}` is not indexed as a Kotlin callable or type"),
        ),
    }
}

/// The declarations a constructor call `Type(...)` names.
///
/// Kotlin indexes a primary constructor as a synthetic `Owner.Owner` callable,
/// but only when it declares parameters: `class Base` has no constructor
/// declaration at all, and the class itself is then the only physical thing the
/// call can point at.
fn kotlin_constructor_outcome(ctx: &KotlinCtx<'_>, type_fqn: &str) -> DefinitionLookupOutcome {
    let simple = type_fqn.rsplit('.').next().unwrap_or(type_fqn);
    let constructors = ctx
        .support
        .fqn_in_any_language(&format!("{type_fqn}.{simple}"))
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect::<Vec<_>>();
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }
    let types = ctx.types_named(type_fqn);
    if types.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{type_fqn}` resolved as a Kotlin type but has no indexed definition"),
        );
    }
    candidates_outcome(types)
}

fn kotlin_callable_outcome(candidates: Vec<CodeUnit>, subject: &str) -> DefinitionLookupOutcome {
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{subject}` is not indexed as a Kotlin callable"),
        );
    }
    candidates_outcome(candidates)
}

/// Resolve a bare name used as a value: a property, an object, an enum entry,
/// or a class named as a qualifier.
fn kotlin_bare_value_outcome(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    name: &str,
) -> DefinitionLookupOutcome {
    let scope = ctx.scope_at(node.start_byte());
    match resolve_kotlin_type_name(name, &scope.as_name_scope(), |candidate| {
        !ctx.values_named(candidate).is_empty()
    }) {
        KotlinTypeName::Resolved(fqn) => candidates_outcome(ctx.values_named(&fqn)),
        KotlinTypeName::Ambiguous => no_definition(
            "ambiguous_kotlin_type",
            format!("`{name}` is bound to different owners by more than one Kotlin star import"),
        ),
        KotlinTypeName::Unresolved => no_definition(
            "no_indexed_definition",
            format!("`{name}` is not indexed as a Kotlin definition"),
        ),
    }
}

/// Resolve the label of a named argument to the callable that declares a
/// parameter of that name.
///
/// Kotlin parameters are not indexed as declarations, and the lexical-definition
/// channel can only address the file the request was made in, so the callable is
/// the finest identity that is correct across files. Proving the parameter
/// exists is what keeps this honest: a label that no candidate declares abstains
/// rather than pointing at a callable it does not belong to.
fn kotlin_named_argument_outcome(
    ctx: &KotlinCtx<'_>,
    argument: Node<'_>,
    label: &str,
) -> DefinitionLookupOutcome {
    let Some(call) = kotlin_enclosing_call(argument) else {
        return no_definition(
            "no_named_argument_owner",
            format!("named argument `{label}` has no enclosing Kotlin call"),
        );
    };
    let Some(callee) = kotlin_callee(call) else {
        return no_definition(
            "no_named_argument_owner",
            format!("named argument `{label}` has no resolvable callee"),
        );
    };
    if callee.kind() != "simple_identifier" {
        return no_definition(
            "no_named_argument_owner",
            format!(
                "named argument `{label}` has a Kotlin `{}` callee that get_definition does not resolve yet",
                callee.kind()
            ),
        );
    }
    let owner =
        kotlin_bare_call_outcome(ctx, callee, ctx.text(callee), Some(kotlin_call_arity(call)));
    if owner.definitions.is_empty() {
        return no_definition(
            "no_named_argument_owner",
            format!("named argument `{label}` has an unresolved Kotlin callee"),
        );
    }
    let declaring = owner
        .definitions
        .into_iter()
        .filter(|unit| ctx.declares_parameter(unit, label))
        .collect::<Vec<_>>();
    if declaring.is_empty() {
        return no_definition(
            "unknown_named_argument",
            format!("no resolved Kotlin callable declares a parameter named `{label}`"),
        );
    }
    candidates_outcome(declaring)
}

/// The `call_expression` or `constructor_invocation` an argument belongs to.
fn kotlin_enclosing_call(argument: Node<'_>) -> Option<Node<'_>> {
    let mut current = argument.parent();
    while let Some(node) = current {
        match node.kind() {
            "call_expression" | "constructor_invocation" => return Some(node),
            "value_arguments" | "call_suffix" | "value_argument" => current = node.parent(),
            _ => return None,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Member access: typing a receiver, then finding the member on that type.
// ---------------------------------------------------------------------------

/// How many receiver hops a chained expression is followed for.
///
/// `a.b().c().d` needs three; a cap keeps a pathological or cyclic chain from
/// turning one request into an unbounded walk, and an exceeded cap abstains
/// rather than guessing.
const MAX_RECEIVER_DEPTH: usize = 8;

/// How many levels of supertype a member lookup walks.
const MAX_MEMBER_HIERARCHY_DEPTH: usize = 8;

/// A typed receiver: the declaration the member must be looked up on, and
/// whether it was named as a type rather than produced as a value.
///
/// The distinction matters because Kotlin exposes a class's companion members
/// through the class name (`Factory.create()`) but not through an instance of
/// it, so only a static qualifier may search the companion.
struct KotlinReceiver {
    owner: CodeUnit,
    static_qualifier: bool,
}

/// Resolve the member of `a.member` / `a?.member` / `a!!.member`.
fn kotlin_member_outcome(
    ctx: &KotlinCtx<'_>,
    suffix: Node<'_>,
    member: &str,
) -> DefinitionLookupOutcome {
    let Some(navigation) = suffix
        .parent()
        .filter(|parent| parent.kind() == "navigation_expression")
    else {
        return no_definition(
            "unsupported_kotlin_reference_shape",
            format!("`{member}` is a Kotlin member access with no receiver expression"),
        );
    };
    let Some(receiver_node) = named_children(navigation).into_iter().next() else {
        return no_definition(
            "unsupported_kotlin_reference_shape",
            format!("`{member}` is a Kotlin member access with no receiver expression"),
        );
    };
    let Some(receiver) = kotlin_receiver(ctx, receiver_node, 0) else {
        return no_definition(
            "receiver_type_unknown",
            format!(
                "the receiver of `{member}` is a Kotlin `{}` expression whose type is not proven",
                receiver_node.kind()
            ),
        );
    };

    // A member access is a call only when the navigation is itself the callee
    // of a call; `a.b` as a value proves no arity.
    let arity = navigation
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
        .filter(|call| kotlin_callee(*call).is_some_and(|callee| callee.id() == navigation.id()))
        .map(kotlin_call_arity);

    let candidates = kotlin_member_candidates(ctx, &receiver, member, arity, suffix.start_byte());
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{member}` is not a member of `{}` or anything it inherits",
                receiver.owner.fq_name()
            ),
        );
    }
    candidates_outcome(candidates)
}

/// Members named `member` reachable through `receiver`.
///
/// The search order is Kotlin's: the receiver's own members, the companion when
/// the receiver was named as a type, then supertypes breadth-first, then
/// extension functions visible at the reference site. Arity steers the search
/// the same way it steers a bare call, with an arity-blind second pass so a
/// missing arity record cannot turn a present declaration into "not found".
fn kotlin_member_candidates(
    ctx: &KotlinCtx<'_>,
    receiver: &KotlinReceiver,
    member: &str,
    arity: Option<usize>,
    site_byte: usize,
) -> Vec<CodeUnit> {
    for required_arity in [arity, None] {
        let mut seen = Vec::new();
        let mut frontier = vec![receiver.owner.clone()];
        for _ in 0..MAX_MEMBER_HIERARCHY_DEPTH {
            let mut next = Vec::new();
            for owner in &frontier {
                let owner_fqn = owner.fq_name();
                if seen.contains(&owner_fqn) {
                    continue;
                }
                seen.push(owner_fqn.clone());

                let mut owners = vec![owner_fqn.clone()];
                if receiver.static_qualifier {
                    owners.extend(ctx.companion_fqns(&owner_fqn));
                }
                for scope in owners {
                    let found = ctx.members_named(&format!("{scope}.{member}"), required_arity);
                    if !found.is_empty() {
                        return found;
                    }
                }

                if let Some(provider) = ctx.analyzer.type_hierarchy_provider() {
                    next.extend(provider.get_direct_ancestors(owner));
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }

        let extensions =
            kotlin_extension_candidates(ctx, receiver, member, required_arity, site_byte);
        if !extensions.is_empty() {
            return extensions;
        }
        if required_arity.is_none() {
            break;
        }
    }
    Vec::new()
}

/// Extension functions named `member` that are in scope at the reference and
/// whose declared receiver type is the receiver's type or one of its supertypes.
///
/// Visibility runs through the ordinary name-resolution ladder, so an extension
/// is found exactly when Kotlin would find it: declared in an enclosing scope,
/// imported, declared in the same package, or star-imported.
fn kotlin_extension_candidates(
    ctx: &KotlinCtx<'_>,
    receiver: &KotlinReceiver,
    member: &str,
    arity: Option<usize>,
    site_byte: usize,
) -> Vec<CodeUnit> {
    let scope = ctx.scope_at(site_byte);
    let conforming = |unit: &CodeUnit| {
        arity.is_none_or(|arity| ctx.accepts_arity(unit, arity))
            && ctx
                .extension_receiver_unit(unit)
                .is_some_and(|declared| ctx.type_conforms_to(&receiver.owner, &declared))
    };
    let resolution = resolve_kotlin_type_name(member, &scope.as_name_scope(), |candidate| {
        ctx.callables_named(candidate).iter().any(conforming)
    });
    let Some(fqn) = resolution.resolved() else {
        return Vec::new();
    };
    ctx.callables_named(&fqn)
        .into_iter()
        .filter(|unit| conforming(unit))
        .collect()
}

/// Type the expression a member is selected from.
fn kotlin_receiver(ctx: &KotlinCtx<'_>, node: Node<'_>, depth: usize) -> Option<KotlinReceiver> {
    if depth > MAX_RECEIVER_DEPTH {
        return None;
    }
    match node.kind() {
        // `a!!.b` and `(a).b` select from the same thing `a` does.
        "postfix_expression" | "parenthesized_expression" => {
            kotlin_receiver(ctx, named_children(node).into_iter().next()?, depth + 1)
        }
        "this_expression" => Some(KotlinReceiver {
            owner: kotlin_this_owner(ctx, node)?,
            static_qualifier: false,
        }),
        "super_expression" => Some(KotlinReceiver {
            owner: kotlin_super_owner(ctx, node)?,
            static_qualifier: false,
        }),
        "as_expression" => {
            let asserted = named_children(node).into_iter().next_back()?;
            Some(KotlinReceiver {
                owner: ctx.resolve_type_unit(
                    &kotlin_type_node_spelling(ctx, asserted)?,
                    &ctx.scope_at(node.start_byte()),
                )?,
                static_qualifier: false,
            })
        }
        "simple_identifier" => kotlin_identifier_receiver(ctx, node, depth),
        "call_expression" | "navigation_expression" => Some(KotlinReceiver {
            owner: kotlin_expression_type(ctx, node, depth)?,
            static_qualifier: false,
        }),
        _ => None,
    }
}

/// Type a bare name used as a receiver: a local binding, a property in scope,
/// or a type named as a static qualifier.
fn kotlin_identifier_receiver(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    depth: usize,
) -> Option<KotlinReceiver> {
    let name = ctx.text(node);
    if let Some(binding) = kotlin_local_binding(node, ctx.source, name) {
        return Some(KotlinReceiver {
            owner: kotlin_binding_type(ctx, binding, depth)?,
            static_qualifier: false,
        });
    }

    let scope = ctx.scope_at(node.start_byte());
    if let Some(owner) = ctx.resolve_type_unit(name, &scope) {
        return Some(KotlinReceiver {
            owner,
            static_qualifier: true,
        });
    }

    // A property of an enclosing declaration, or a top-level/imported one.
    let fqn = resolve_kotlin_type_name(name, &scope.as_name_scope(), |candidate| {
        ctx.support
            .fqn_in_any_language(candidate)
            .iter()
            .any(CodeUnit::is_field)
    })
    .resolved()?;
    let property = ctx
        .support
        .fqn_in_any_language(&fqn)
        .into_iter()
        .find(CodeUnit::is_field)?;
    Some(KotlinReceiver {
        owner: ctx.declared_type_of(&property, depth)?,
        static_qualifier: false,
    })
}

/// The class a `this` expression denotes.
///
/// A label (`this@Outer`) picks the named enclosing declaration; an unlabelled
/// `this` is the innermost one.
fn kotlin_this_owner(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<CodeUnit> {
    let label = first_named_child_of_kind(node, "label").map(|label| {
        ctx.text(label)
            .trim_start_matches('@')
            .trim_end_matches('@')
            .to_string()
    });
    let mut current = ctx.enclosing_class_at(node.start_byte());
    while let Some(unit) = current {
        match label.as_deref() {
            Some(label) if unit.identifier() != label => {
                current = ctx.analyzer.parent_of(&unit).filter(CodeUnit::is_class);
            }
            _ => return Some(unit),
        }
    }
    None
}

/// The class a `super` expression denotes: the first direct ancestor of the
/// enclosing class, or the named one in `super<Base>`.
fn kotlin_super_owner(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<CodeUnit> {
    let enclosing = ctx.enclosing_class_at(node.start_byte())?;
    let named = first_named_child_of_kind(node, "user_type")
        .and_then(|user_type| kotlin_type_node_spelling(ctx, user_type));
    let ancestors = ctx
        .analyzer
        .type_hierarchy_provider()?
        .get_direct_ancestors(&enclosing);
    match named {
        Some(named) => ancestors
            .into_iter()
            .find(|ancestor| ancestor.identifier() == named || ancestor.fq_name() == named),
        None => ancestors.into_iter().next(),
    }
}

/// The type an expression evaluates to, as an indexed declaration.
fn kotlin_expression_type(ctx: &KotlinCtx<'_>, node: Node<'_>, depth: usize) -> Option<CodeUnit> {
    if depth > MAX_RECEIVER_DEPTH {
        return None;
    }
    match node.kind() {
        "postfix_expression" | "parenthesized_expression" => {
            kotlin_expression_type(ctx, named_children(node).into_iter().next()?, depth + 1)
        }
        "call_expression" => {
            let callee = kotlin_callee(node)?;
            let target = kotlin_call_target(ctx, node, callee, depth)?;
            // A constructor call evaluates to the class it constructs; any
            // other call evaluates to its declared return type.
            if target.is_class() {
                return Some(target);
            }
            ctx.declared_type_of(&target, depth)
        }
        "navigation_expression" => {
            let suffix = named_children(node)
                .into_iter()
                .find(|child| child.kind() == "navigation_suffix")?;
            let member = first_named_child_of_kind(suffix, "simple_identifier")?;
            let receiver =
                kotlin_receiver(ctx, named_children(node).into_iter().next()?, depth + 1)?;
            let target = kotlin_member_candidates(
                ctx,
                &receiver,
                ctx.text(member),
                None,
                suffix.start_byte(),
            )
            .into_iter()
            .next()?;
            ctx.declared_type_of(&target, depth)
        }
        "simple_identifier" => kotlin_receiver(ctx, node, depth + 1).map(|receiver| receiver.owner),
        "as_expression" => {
            let asserted = named_children(node).into_iter().next_back()?;
            ctx.resolve_type_unit(
                &kotlin_type_node_spelling(ctx, asserted)?,
                &ctx.scope_at(node.start_byte()),
            )
        }
        "object_literal" => None,
        _ => None,
    }
}

/// The single declaration a call resolves to, when it resolves to exactly one.
fn kotlin_call_target(
    ctx: &KotlinCtx<'_>,
    call: Node<'_>,
    callee: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    let outcome = match callee.kind() {
        "simple_identifier" => {
            kotlin_bare_call_outcome(ctx, callee, ctx.text(callee), Some(kotlin_call_arity(call)))
        }
        "navigation_expression" => {
            let suffix = named_children(callee)
                .into_iter()
                .find(|child| child.kind() == "navigation_suffix")?;
            let member = first_named_child_of_kind(suffix, "simple_identifier")?;
            let receiver =
                kotlin_receiver(ctx, named_children(callee).into_iter().next()?, depth + 1)?;
            return kotlin_member_candidates(
                ctx,
                &receiver,
                ctx.text(member),
                Some(kotlin_call_arity(call)),
                suffix.start_byte(),
            )
            .into_iter()
            .next();
        }
        _ => return None,
    };
    let mut definitions = outcome.definitions;
    (definitions.len() == 1).then(|| definitions.remove(0))
}

/// The declaration a `variable_declaration`, `parameter`, or `class_parameter`
/// node binds a type to.
fn kotlin_binding_type(ctx: &KotlinCtx<'_>, binding: Node<'_>, depth: usize) -> Option<CodeUnit> {
    let scope = ctx.scope_at(binding.start_byte());
    if let Some(spelled) = kotlin_declared_type_spelling(ctx, binding)
        && let Some(unit) = ctx.resolve_type_unit(&spelled, &scope)
    {
        return Some(unit);
    }
    // No written type: the initializer of the enclosing property is the only
    // other proof. Kotlin's full inference is not modelled, so anything that is
    // not a call or a cast stays unknown rather than being guessed.
    let property = binding
        .parent()
        .filter(|parent| parent.kind() == "property_declaration")?;
    let initializer = named_children(property)
        .into_iter()
        .rev()
        .find(|child| kotlin_is_expression_kind(child.kind()))?;
    kotlin_expression_type(ctx, initializer, depth + 1)
}

/// The `variable_declaration`, `parameter`, or `class_parameter` node that binds
/// `name` at `node`, searching enclosing scopes innermost first.
///
/// Only bindings that begin before the reference are considered, which is what
/// keeps a later same-named local from answering for an earlier reference.
fn kotlin_local_binding<'tree>(node: Node<'tree>, source: &str, name: &str) -> Option<Node<'tree>> {
    let reference_start = node.start_byte();
    let mut current = node.parent();
    while let Some(scope) = current {
        let mut stack = named_children(scope);
        while let Some(candidate) = stack.pop() {
            if candidate.start_byte() > reference_start {
                continue;
            }
            match candidate.kind() {
                "variable_declaration" | "parameter" | "class_parameter" => {
                    if kotlin_binding_name(candidate, source) == Some(name) {
                        return Some(candidate);
                    }
                }
                // Do not descend into a nested declaration: its locals are not
                // in scope here, and a same-named one there must not answer.
                "class_declaration"
                | "object_declaration"
                | "companion_object"
                | "function_declaration" => continue,
                _ => stack.extend(named_children(candidate)),
            }
        }
        current = scope.parent();
    }
    None
}

fn kotlin_binding_name<'a>(binding: Node<'_>, source: &'a str) -> Option<&'a str> {
    first_named_child_of_kind(binding, "simple_identifier")?
        .utf8_text(source.as_bytes())
        .ok()
}

/// Whether a node kind can appear as the value half of a property declaration.
fn kotlin_is_expression_kind(kind: &str) -> bool {
    matches!(
        kind,
        "call_expression"
            | "navigation_expression"
            | "as_expression"
            | "simple_identifier"
            | "parenthesized_expression"
            | "postfix_expression"
            | "object_literal"
    )
}

/// The declaration node covering `range`.
///
/// The smallest covering node is not always the declaration: an `enum_entry`
/// spans exactly its own name, so its `simple_identifier` child covers the same
/// bytes and would win. Climbing back out to the outermost node with the same
/// span picks the declaration rather than the name inside it.
fn kotlin_declaration_node<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    let mut node = smallest_named_node_covering(root, range.start_byte, range.end_byte)?;
    while let Some(parent) = node.parent() {
        if parent.start_byte() != node.start_byte() || parent.end_byte() != node.end_byte() {
            break;
        }
        node = parent;
    }
    Some(node)
}

/// The return type a function declaration writes, if it wrote one.
///
/// The grammar gives the return type no field, but it is the only bare type
/// node among a `function_declaration`'s children: the parameters live inside
/// `function_value_parameters` and the receiver behind the `receiver` field.
fn kotlin_declared_return_type_spelling(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<String> {
    let receiver = node.child_by_field_name("receiver").map(|node| node.id());
    named_children(node)
        .into_iter()
        .filter(|child| Some(child.id()) != receiver)
        .find_map(|child| kotlin_type_node_spelling(ctx, child))
}

/// The dotted name a type node spells, or `None` for a shape that names no
/// nominal type (a function type, a star projection).
fn kotlin_type_node_spelling(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<String> {
    match node.kind() {
        "user_type" => {
            let segments = named_children(node)
                .into_iter()
                .filter(|child| child.kind() == "type_identifier")
                .map(|child| ctx.text(child))
                .collect::<Vec<_>>();
            (!segments.is_empty()).then(|| segments.join("."))
        }
        "nullable_type" | "not_nullable_type" | "parenthesized_type" | "receiver_type"
        | "type_projection" => named_children(node)
            .into_iter()
            .find_map(|child| kotlin_type_node_spelling(ctx, child)),
        _ => None,
    }
}

/// The type written on a binding, if it was written at all.
fn kotlin_declared_type_spelling(ctx: &KotlinCtx<'_>, binding: Node<'_>) -> Option<String> {
    named_children(binding)
        .into_iter()
        .find_map(|child| kotlin_type_node_spelling(ctx, child))
}
