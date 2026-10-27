//! Language rules available without an analyzer or store.

use crate::analyzer::fq_name::FqName;
use crate::analyzer::model::LanguageDialect;
use crate::analyzer::resolution_facts::IntrinsicTypeKind;
use crate::analyzer::structural::spec::StructuralSpec;
use crate::analyzer::usages::reference_site::node_range;
use crate::analyzer::{CodeUnit, Language, ProjectFile, Range};

/// Which of a language's grammars parses one file.
///
/// Named for the grammar, not for the dialect that asked for it: two dialects
/// select [`ParserFlavor::Tsx`], TypeScript's `.tsx` and JavaScript's `.jsx`
/// (#3322), and a language that ships one grammar answers [`Self::Default`]
/// for every dialect it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserFlavor {
    Default,
    Tsx,
}

impl ParserFlavor {
    pub const fn for_dialect(dialect: LanguageDialect) -> Self {
        match dialect {
            // C and C++ share one grammar; the dialect only changes how the
            // parsed tree is interpreted, never which parser produces it.
            LanguageDialect::Standard(_) | LanguageDialect::CppC => Self::Default,
            LanguageDialect::TypeScriptTsx | LanguageDialect::JavaScriptJsx => Self::Tsx,
        }
    }
}

/// Language syntax and rules independent of query-time engine state.
pub trait LanguageKnowledge: Send + Sync {
    /// Promote the exact static operand type names for one numeric expression
    /// to the intrinsic result type. Names come from selected type descriptors,
    /// never source-text parsing.
    fn numeric_promotion(
        &self,
        _operands: &[Option<&str>],
    ) -> Option<(IntrinsicTypeKind, &'static str)> {
        None
    }

    /// Whether an inferred local's static type is exactly its initializer's
    /// type. Later writes must conform to that type but never widen it, so
    /// they contribute observed values without feeding the declared type.
    /// Languages whose inference reads later writes keep the default.
    fn inferred_local_type_is_initializer_type(&self) -> bool {
        false
    }

    /// Select an operand whose static type proves string concatenation.
    /// Other operands need not have known types once this witness exists.
    fn string_concatenation_operand(&self, _operands: &[Option<&str>]) -> Option<usize> {
        None
    }

    /// The `Language` variant this support serves. Must equal the registry match key.
    fn language(&self) -> Language;

    /// Whether an invocation may apply a value selected by lexical or member
    /// binding. The declared value type must still prove call applicability.
    fn call_may_apply_value(&self) -> bool {
        false
    }

    /// Whether invocation applicability may select among callee declarations.
    /// Languages with applicability-independent binding may keep a positioned
    /// callee reference complete while its call obligation remains incomplete.
    fn call_applicability_may_select_callee(&self) -> bool {
        true
    }

    /// Invocation validity cannot change a callable's written result type.
    /// Binding and result projection retain every other kind of uncertainty.
    fn callable_result_is_applicability_independent(&self) -> bool {
        false
    }

    /// Publish the established local-binding diagnostic for a proven native
    /// lexical binding that has no indexed declaration unit.
    fn native_local_binding_diagnostic(&self) -> bool {
        false
    }

    /// Whether an unbound call supplies a target's instance receiver as its
    /// first written actual. The target, not the call's qualifier, establishes
    /// whether an instance receiver exists.
    fn unbound_call_passes_receiver_as_argument(&self) -> bool {
        false
    }

    /// Property locations represent keyed container elements in this language.
    /// This supplies container taint to element reads without proving runtime behavior.
    fn keyed_property_reads_container_element(&self) -> bool {
        false
    }

    /// Callee routes for a language that binds the innermost term family
    /// before checking invocation. Equal ordinals form one overload set;
    /// later routes are fallback bindings, never applicability fallbacks.
    fn call_target_lookup_routes(
        &self,
    ) -> Option<&'static [(u32, crate::analyzer::resolution_facts::ResolutionNamespace)]> {
        None
    }

    /// Unexpanded item generators preserve existing authored/imported bindings.
    /// Their missing names and potentially generated members remain open.
    fn generated_items_cannot_shadow_bindings(&self) -> bool {
        false
    }

    /// The module represented by the file itself, when this language has one.
    /// Use the same constructor as the storage adapter's path module projection.
    /// Such a module has no declaration token and navigates to file start;
    /// source-declared modules use their ordinary declaration name ranges.
    fn path_synthetic_module_unit(
        &self,
        _project: &dyn crate::analyzer::project::Project,
        _file: &ProjectFile,
    ) -> Option<CodeUnit> {
        None
    }

    /// Separator between a package name and its parent. Only Go and C++ differ from the
    /// dotted default.
    fn package_separator(&self) -> &'static str {
        "."
    }

    /// The separator this language writes between the segments of a qualified callee
    /// path *in source*: `java.net.URLDecoder.decode` against `std::str::from_utf8`.
    /// Rust (#2596) and C++ (#2606) write `::`; every other language keeps the dotted
    /// default.
    ///
    /// This decides only how the spelling is cut. The canonical owner published from
    /// it is always dot-joined, because that is how authored procedure-summary symbols
    /// are indexed.
    fn qualified_call_separator(&self) -> &'static str {
        "."
    }

    /// Whether this language's external surface is reached through owners that
    /// carry only one segment (#2598).
    ///
    /// The dot in `java.net.URLDecoder.decode` is the proxy the unmaterialized
    /// external route was born with: an owner that already spells its own
    /// qualification needs no import or type resolution to name an identity.
    /// That proxy holds for Java and Rust and fails outright for JavaScript and
    /// TypeScript, whose entire standard surface is `JSON.parse`,
    /// `Buffer.from`, `crypto.randomUUID` and `path.join` -- every one of them
    /// a single segment.
    ///
    /// Saying `true` here does not admit every single-segment owner. It states
    /// that such an owner *can* be an identity in this language, so the
    /// classification stage consults
    /// the engine's `single_segment_external_owner` hook to decide each one.
    fn publishes_single_segment_external_owners(&self) -> bool {
        false
    }

    /// How a fully qualified name is spelled for a reader. The default is the indexed
    /// spelling itself; the three languages that override strip indexer-only decoration
    /// their users never type (Scala's object `$`, C#'s generic arity and `global::`
    /// prefix, TypeScript's `$static` static-member marker).
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol.to_string()
    }

    /// The decoration [`Self::display_symbol_name`] removes, expressed as a change to
    /// the *structured* name instead of an edit to its rendering. `None` when `fq`
    /// carries no decoration for this language to remove, which is the common case and
    /// costs the caller nothing.
    ///
    /// A rendering cannot answer this question. [`FqName::render_native`] appends
    /// exactly one `$` for each [`crate::analyzer::fq_name::SegmentKind::Companion`] segment, and a Scala object's
    /// own name may end in `$` too -- `object ConstellationNode$` is legal Scala and
    /// Constellation-Labs/constellation writes it -- so the rendered name ends in two
    /// `$`, one decoration and one the source wrote. Reading that string back with
    /// `trim_end_matches('$')` removed both and printed
    /// `org.constellation.ConstellationNode`, a spelling no declaration answers (#3505).
    /// Changing a segment's *kind* leaves every segment's text intact, so only the
    /// renderer's own suffix disappears.
    fn undecorated_fq_name(&self, _fq: &FqName) -> Option<FqName> {
        None
    }

    /// How a declaration's identifier is written at its declaration site, which is what
    /// range selection has to match against source text. Same decoration as
    /// [`Self::display_symbol_name`] removes, applied to a single identifier.
    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        identifier
    }

    /// An additional spelling of one symbol-path segment that a query may reasonably use.
    /// The default offers no alternative; C# offers the arity-free form, because indexed
    /// generic names carry `` Type`1 `` and nobody types the arity (#1063).
    fn alias_name_segment<'s>(&self, segment: &'s str) -> &'s str {
        segment
    }

    /// The source range of the identifier `node` carries. The default is the node's own
    /// span; Ruby narrows it, because its symbol literals include a leading `:` or
    /// surrounding quotes that are not part of the name.
    fn declaration_name_range(&self, node: tree_sitter::Node<'_>, _source: &str) -> Range {
        node_range(node)
    }

    /// The identifier a symbol-literal node names, or `None` when the node is not one.
    /// Only Ruby has a literal form whose text differs from the name it denotes.
    fn symbol_literal_name(&self, _node: tree_sitter::Node<'_>, _source: &str) -> Option<String> {
        None
    }

    /// The callee of a call whose grammar names it positionally rather than by field, or
    /// `None` when the generic field lookup already finds it.
    fn call_callee_node<'t>(&self, _call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// The identifier a declaration names, for languages whose grammar names it
    /// positionally rather than by field, or `None` when the field lookup or
    /// document-order search already finds it.
    fn declaration_name_node<'t>(
        &self,
        _declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// The argument-list nodes of a call whose grammar nests them out of reach of the
    /// generic field and child-kind lookup. `Some` replaces that lookup entirely, so an
    /// empty vector means "this call has no arguments", not "look elsewhere".
    fn call_argument_nodes<'t>(
        &self,
        _call: tree_sitter::Node<'t>,
    ) -> Option<Vec<tree_sitter::Node<'t>>> {
        None
    }

    /// The identifier naming the callee of a factory call, for languages whose call shape
    /// the framework's per-grammar table cannot express through field lookups alone.
    fn factory_name_node<'t>(&self, _call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// The default expression of a formal parameter whose grammar does not
    /// expose that expression through a named field. `None` leaves the shared
    /// named-field lookup in charge.
    fn positional_parameter_default<'t>(
        &self,
        _parameter: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// Whether `node`, already recognized as a local declaration by node kind, is one this
    /// language's grammar produces where no local binding exists. C++ says yes for an
    /// `init_declarator` inside a recovered exported class body, where the parse shape of a
    /// member declaration is indistinguishable from a local one.
    fn skips_local_declaration(&self, _node: tree_sitter::Node<'_>, _source: &str) -> bool {
        false
    }

    /// Whether the lexical resolver must traverse syntax after the focused byte to find
    /// declarations that bind earlier source positions. A declaration found there is
    /// still accepted only when the engine's `local_declaration_binding_scope` hook proves that the
    /// current syntax scope owns it.
    fn scans_local_declarations_after_focus(&self) -> bool {
        false
    }

    /// This language's tree-sitter grammar for `flavor`. The parameter exists for
    /// TypeScript, whose `.ts` and `.tsx` files parse under distinct grammars while
    /// sharing one adapter; every other language answers the same grammar for both.
    fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language;

    /// This language's normalized structural-search adapter, the spec `query_code` runs
    /// against.
    fn structural_spec(&self) -> &'static dyn StructuralSpec;

    /// This language's tree-sitter highlights query, or `None` when it ships none.
    /// Every registered language currently answers `Some`; the option is here so a
    /// future one can be analyzable without shipping highlights instead of returning an
    /// empty query that silently produces no captures.
    fn highlight_query(&self) -> Option<&'static str>;
}
