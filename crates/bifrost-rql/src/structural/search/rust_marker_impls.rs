//! Query-local marker impl facts. Syntax and worklists live only for this query.

use super::*;
use crate::analyzer::CodeUnitType;
use brokk_bifrost_analysis::analyzer::structural::provider::{
    StructuralPreparedSyntax, StructuralSyntaxLimitedOutcome,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupRequest,
    resolve_definition_batch_with_source_and_cancellation,
};
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use brokk_bifrost_rust_analysis::analyzer::rust::rust_path_segments;
use tree_sitter::Node;

use super::results::CodeQueryRustMarkerUse;

#[derive(Debug, Clone)]
pub(super) struct RustMarkerImplValue {
    pub(super) file: ProjectFile,
    pub(super) byte_span: std::ops::Range<usize>,
    pub(super) row: CodeQueryRustMarkerImpl,
}

pub(super) struct RustMarkerImplsResult {
    incompleteness: Incompleteness,
    pub(super) rows: Vec<RustMarkerImplValue>,
    pub(super) reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct MarkerIncomplete {
    message: String,
    incompleteness: Incompleteness,
}

impl From<&str> for MarkerIncomplete {
    fn from(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            incompleteness: Incompleteness::Operational(DerivationExecutionCause::Provider),
        }
    }
}

type FileRevision = (ProjectFile, Option<WorkspaceContentIdentity>);
type SyntaxMemo =
    HashMap<FileRevision, Result<Option<Arc<StructuralPreparedSyntax>>, MarkerIncomplete>>;

// The workspace revision also covers dependencies consulted by definition lookup.
// This memo belongs to QueryExecutionState and is dropped with that query.
#[derive(Default)]
pub(super) struct RustMarkerImplsCache {
    syntax: CaptureScopedMemo<SyntaxMemo>,
    files: CaptureScopedMemo<HashMap<FileRevision, Result<MarkerImplFile, MarkerIncomplete>>>,
    methods: CaptureScopedMemo<HashMap<CodeUnit, MethodInventory>>,
}

struct MarkerImplFile {
    syntax: Arc<StructuralPreparedSyntax>,
    bindings: Bindings,
    candidates: Vec<MarkerImplCandidate>,
}

struct MarkerImplCandidate {
    span: std::ops::Range<usize>,
    marker_name: &'static str,
    trait_proof: &'static str,
    self_outcome: DefinitionLookupOutcome,
    self_name: Option<String>,
}

impl MarkerImplFile {
    fn read(ctx: &mut Context<'_>, file: &ProjectFile) -> Result<Self, MarkerIncomplete> {
        let syntax = ctx
            .syntax(file)?
            .ok_or("Rust marker impl source syntax unavailable")?;
        let source = syntax.prepared().source();
        let bindings = Bindings::read(ctx, syntax.prepared().tree().root_node(), source)?;
        let mut candidates = Vec::new();
        let mut stack = vec![syntax.prepared().tree().root_node()];
        while let Some(node) = stack.pop() {
            ctx.charge()?;
            stack.extend(children(node).into_iter().rev());
            if node.kind() != "impl_item" {
                continue;
            }
            let Some(trait_node) = node.child_by_field_name("trait") else {
                continue;
            };
            let mut cursor = node.walk();
            let mut unsafe_impl = false;
            let mut negative = false;
            for child in node.children(&mut cursor) {
                unsafe_impl |= child.kind() == "unsafe";
                negative |= child.kind() == "!";
            }
            if !unsafe_impl || negative {
                continue;
            }
            let bindings = Bindings::read(ctx, node, source)?;
            let trait_head = head(trait_node);
            let segments = path(trait_head, source);
            let Some(name) = segments.last() else {
                continue;
            };
            let imported_marker = segments.len() == 1
                && bindings.imports.get(name).is_some_and(|targets| {
                    targets.iter().any(|target| {
                        matches!(target.as_slice(), [root, module, marker]
                            if matches!(root.as_str(), "std" | "core")
                                && module == "marker"
                                && matches!(marker.as_str(), "Send" | "Sync"))
                    })
                });
            if !matches!(name.as_str(), "Send" | "Sync") && !imported_marker {
                continue;
            }
            let outcome = ctx.lookup(file, source, trait_head)?;
            let Some((marker_name @ ("Send" | "Sync"), trait_proof)) =
                marker(&outcome, trait_head, source, &bindings)
            else {
                continue;
            };
            let self_type = node.child_by_field_name("type").expect("impl self type");
            let self_outcome = ctx.lookup(file, source, head(self_type))?;
            candidates.push(MarkerImplCandidate {
                span: node.byte_range(),
                marker_name,
                trait_proof,
                self_outcome,
                self_name: path(head(self_type), source).pop(),
            });
        }
        Ok(Self {
            syntax,
            bindings,
            candidates,
        })
    }
}

struct Context<'a> {
    analyzer: &'a dyn IAnalyzer,
    syntax_memo: &'a mut SyntaxMemo,
    revision: Option<WorkspaceContentIdentity>,
    budget: &'a mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: &'a CancellationToken,
}

impl Context<'_> {
    fn charge(&mut self) -> Result<(), MarkerIncomplete> {
        if self.cancellation.is_cancelled() {
            return Err(MarkerIncomplete {
                message: "Rust marker impl query cancelled".into(),
                incompleteness: Incompleteness::Operational(DerivationExecutionCause::Cancelled),
            });
        }
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            self.budget.fact_nodes,
            self.limits.max_fact_nodes,
        )
        .allows(1)
        {
            return Err(MarkerIncomplete {
                message: "Rust marker impl syntax work budget exceeded".into(),
                incompleteness: Incompleteness::Operational(DerivationExecutionCause::Budget),
            });
        }
        self.budget.fact_nodes += 1;
        Ok(())
    }

    fn syntax(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Option<Arc<StructuralPreparedSyntax>>, MarkerIncomplete> {
        let key = (file.clone(), self.revision);
        if let Some(outcome) = self.syntax_memo.get(&key) {
            return outcome.clone();
        }
        let outcome = self.read_syntax(file).map(|syntax| syntax.map(Arc::new));
        self.syntax_memo.insert(key, outcome.clone());
        outcome
    }

    fn read_syntax(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Option<StructuralPreparedSyntax>, MarkerIncomplete> {
        self.charge()?;
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            self.budget.scanned_files,
            self.limits.max_scanned_files,
        )
        .allows(1)
        {
            return Err(MarkerIncomplete {
                message: "Rust marker impl file budget exceeded".into(),
                incompleteness: Incompleteness::Operational(DerivationExecutionCause::Budget),
            });
        }
        let provider = self
            .analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Rust)
            .ok_or("Rust syntax provider unavailable")?;
        let remaining = self
            .limits
            .max_scanned_source_bytes
            .saturating_sub(self.budget.scanned_source_bytes);
        let syntax =
            match provider.structural_syntax_limited(file, remaining, Some(self.cancellation)) {
                StructuralSyntaxLimitedOutcome::Available(syntax) => syntax,
                StructuralSyntaxLimitedOutcome::Unavailable => return Ok(None),
                outcome => {
                    let cause = match outcome {
                        StructuralSyntaxLimitedOutcome::Cancelled => {
                            DerivationExecutionCause::Cancelled
                        }
                        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
                            DerivationExecutionCause::Budget
                        }
                        _ => unreachable!("available and unavailable outcomes returned above"),
                    };
                    return Err(MarkerIncomplete {
                        message: format!(
                            "Rust marker impl syntax unavailable for {}: {outcome:?}",
                            file.rel_path().display()
                        ),
                        incompleteness: Incompleteness::Operational(cause),
                    });
                }
            };
        self.budget.scanned_files += 1;
        self.budget.scanned_source_bytes += syntax.prepared().source().len();
        Ok(Some(syntax))
    }

    fn lookup(
        &mut self,
        file: &ProjectFile,
        source: &str,
        node: Node<'_>,
    ) -> Result<DefinitionLookupOutcome, MarkerIncomplete> {
        self.charge()?;
        let mut outcomes = resolve_definition_batch_with_source_and_cancellation(
            self.analyzer,
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(node.start_byte()),
                end_byte: Some(node.end_byte()),
            }],
            file.clone(),
            Arc::from(source),
            self.cancellation,
        );
        assert_eq!(
            outcomes.len(),
            1,
            "one definition request returns one outcome"
        );
        if self.cancellation.is_cancelled() {
            return Err(MarkerIncomplete {
                message: "Rust marker definition lookup cancelled".into(),
                incompleteness: Incompleteness::Operational(DerivationExecutionCause::Cancelled),
            });
        }
        Ok(outcomes.pop().unwrap())
    }
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn head(node: Node<'_>) -> Node<'_> {
    if node.kind() == "generic_type" {
        node.child_by_field_name("type")
            .expect("generic type has head")
    } else {
        node
    }
}

fn path(node: Node<'_>, source: &str) -> Vec<String> {
    rust_path_segments(node)
        .unwrap_or_default()
        .into_iter()
        .map(|node| text(node, source).to_owned())
        .collect()
}

#[derive(Default)]
struct Bindings {
    types: HashMap<String, usize>,
    imports: HashMap<String, Vec<Vec<String>>>,
}

impl Bindings {
    fn read(ctx: &mut Context<'_>, site: Node<'_>, source: &str) -> Result<Self, MarkerIncomplete> {
        let mut containers = Vec::new();
        let mut node = site;
        loop {
            ctx.charge()?;
            let module = node.kind() == "source_file"
                || (node.kind() == "declaration_list"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "mod_item"));
            if module || node.kind() == "block" {
                containers.push(node);
            }
            if module {
                break;
            }
            node = node
                .parent()
                .ok_or("Rust marker binding scope unavailable")?;
        }
        let mut result = Self::default();
        let mut seen = HashSet::default();
        // Blocks inherit item bindings through the enclosing module, but a
        // nested module does not inherit its parent module's bindings.
        for root in containers {
            let mut scoped = Self::default();
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                ctx.charge()?;
                if matches!(
                    node.kind(),
                    "struct_item" | "enum_item" | "union_item" | "trait_item" | "type_item"
                ) && let Some(name) = node.child_by_field_name("name")
                {
                    *scoped
                        .types
                        .entry(text(name, source).to_owned())
                        .or_default() += 1;
                }
                if node.kind() == "use_declaration" {
                    let mut imports = vec![(
                        node.child_by_field_name("argument")
                            .expect("use has argument"),
                        Vec::new(),
                    )];
                    while let Some((argument, prefix)) = imports.pop() {
                        ctx.charge()?;
                        match argument.kind() {
                            "scoped_use_list" => {
                                let mut prefix = prefix;
                                if let Some(p) = argument.child_by_field_name("path") {
                                    prefix.extend(path(p, source));
                                }
                                imports.push((
                                    argument
                                        .child_by_field_name("list")
                                        .expect("scoped use has list"),
                                    prefix,
                                ));
                            }
                            "use_list" => {
                                for child in children(argument) {
                                    imports.push((child, prefix.clone()));
                                }
                            }
                            "use_as_clause" => {
                                let alias = text(
                                    argument.child_by_field_name("alias").expect("use alias"),
                                    source,
                                );
                                let mut target = prefix;
                                target.extend(path(
                                    argument.child_by_field_name("path").expect("use path"),
                                    source,
                                ));
                                scoped
                                    .imports
                                    .entry(alias.to_owned())
                                    .or_default()
                                    .push(target);
                            }
                            _ => {
                                let mut target = prefix;
                                target.extend(path(argument, source));
                                if let Some(name) = target.last() {
                                    scoped.imports.entry(name.clone()).or_default().push(target);
                                }
                            }
                        }
                    }
                }
                if node == root {
                    stack.extend(children(node));
                }
            }

            let names = scoped
                .types
                .keys()
                .chain(scoped.imports.keys())
                .cloned()
                .collect::<HashSet<_>>();
            for name in names {
                if seen.insert(name.clone()) {
                    if let Some(count) = scoped.types.remove(&name) {
                        result.types.insert(name.clone(), count);
                    }
                    if let Some(targets) = scoped.imports.remove(&name) {
                        result.imports.insert(name, targets);
                    }
                }
            }
        }
        Ok(result)
    }

    fn unshadowed(&self, name: &str, canonical: &[String]) -> bool {
        !self.types.contains_key(name)
            && self
                .imports
                .get(name)
                .is_none_or(|targets| targets.iter().all(|target| target == canonical))
    }
}

fn canonical_marker_name(name: &str) -> bool {
    matches!(name, "Send" | "Sync" | "PhantomData")
}

fn resolved_marker(name: &str) -> Option<&'static str> {
    match name {
        "core::marker::Send" | "std::marker::Send" => Some("Send"),
        "core::marker::Sync" | "std::marker::Sync" => Some("Sync"),
        "core::marker::PhantomData" | "std::marker::PhantomData" => Some("PhantomData"),
        _ => None,
    }
}

fn marker(
    outcome: &DefinitionLookupOutcome,
    node: Node<'_>,
    source: &str,
    bindings: &Bindings,
) -> Option<(&'static str, &'static str)> {
    let names = outcome
        .definitions
        .iter()
        .map(CodeUnit::fq_name_str)
        .chain(
            outcome
                .modeled_definitions
                .iter()
                .map(|symbol| symbol.qualified_name.as_str()),
        )
        .collect::<Vec<_>>();
    if !names.is_empty() {
        return (names.len() == 1)
            .then(|| resolved_marker(names[0]))
            .flatten()
            .map(|name| (name, "resolved"));
    }
    let segments = path(node, source);
    let name = segments.last()?.as_str();
    if segments.len() == 1
        && let Some(targets) = bindings.imports.get(name)
    {
        let [target] = targets.as_slice() else {
            return None;
        };
        let [root, module, imported] = target.as_slice() else {
            return None;
        };
        if matches!(root.as_str(), "std" | "core") && module == "marker" {
            return match imported.as_str() {
                "Send" => Some(("Send", "import_alias")),
                "Sync" => Some(("Sync", "import_alias")),
                "PhantomData" => Some(("PhantomData", "import_alias")),
                _ => None,
            };
        }
        return None;
    }
    if !canonical_marker_name(name) {
        return None;
    }
    let canonical = vec!["std".into(), "marker".into(), name.to_owned()];
    let core = vec!["core".into(), "marker".into(), name.to_owned()];
    let accepted = segments == canonical || segments == core || segments.len() == 1;
    if !accepted || !(bindings.unshadowed(name, &canonical) || bindings.unshadowed(name, &core)) {
        return None;
    }
    Some((
        match name {
            "Send" => "Send",
            "Sync" => "Sync",
            _ => "PhantomData",
        },
        "prelude_name",
    ))
}

fn closed_std_bound(
    outcome: &DefinitionLookupOutcome,
    node: Node<'_>,
    source: &str,
    bindings: &Bindings,
) -> bool {
    // Only these ordinary std traits close without implying either marker.
    let canonical = [
        ("Clone", "clone"),
        ("Debug", "fmt"),
        ("Hash", "hash"),
        ("Eq", "cmp"),
        ("Ord", "cmp"),
        ("Default", "default"),
        ("Copy", "marker"),
    ];
    let names = outcome
        .definitions
        .iter()
        .map(CodeUnit::fq_name_str)
        .chain(
            outcome
                .modeled_definitions
                .iter()
                .map(|symbol| symbol.qualified_name.as_str()),
        )
        .collect::<Vec<_>>();
    if !names.is_empty() {
        return names.len() == 1
            && canonical.iter().any(|(name, module)| {
                ["std", "core"]
                    .iter()
                    .any(|root| names[0] == format!("{root}::{module}::{name}"))
            });
    }
    let parts = path(node, source);
    canonical.iter().any(|(name, module)| {
        ["std", "core"].iter().any(|root| {
            let target = vec![(*root).to_owned(), (*module).to_owned(), (*name).to_owned()];
            (parts == target || parts == [*name]) && bindings.unshadowed(name, &target)
        })
    })
}

fn type_node_for_unit<'a>(
    ctx: &mut Context<'_>,
    unit: &CodeUnit,
    syntax: &'a StructuralPreparedSyntax,
    kinds: &[&str],
) -> Result<Option<Node<'a>>, MarkerIncomplete> {
    let source = syntax.prepared().source();
    let ranges = ctx.analyzer.ranges_of(unit);
    let mut stack = vec![syntax.prepared().tree().root_node()];
    while let Some(node) = stack.pop() {
        ctx.charge()?;
        if kinds.contains(&node.kind())
            && node
                .child_by_field_name("name")
                .is_some_and(|name| text(name, source) == unit.terminal_name())
            && ranges.iter().any(|range| {
                range.start_byte <= node.start_byte() && range.end_byte >= node.end_byte()
            })
        {
            return Ok(Some(node));
        }
        stack.extend(children(node));
    }
    Ok(None)
}

fn marker_bounds(
    ctx: &mut Context<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &Bindings,
    bounds: &[Node<'_>],
) -> Result<(bool, bool, bool, Incompleteness), MarkerIncomplete> {
    let mut send = false;
    let mut sync = false;
    let mut open = false;
    let mut incompleteness = Incompleteness::Content;
    for &bound in bounds {
        let mut worklist = Vec::new();
        let mut visited = HashSet::default();
        classify_bound(
            ctx,
            file,
            source,
            bindings,
            bound,
            &mut send,
            &mut sync,
            &mut open,
            &mut worklist,
        )?;
        while let Some(unit) = worklist.pop() {
            if !visited.insert(unit.clone()) {
                continue;
            }
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                visited.len(),
                16,
            )
            .allows(1)
            {
                incompleteness = incompleteness.combine(Incompleteness::Operational(
                    DerivationExecutionCause::Budget,
                ));
                open = true;
                break;
            }
            let Some(syntax) = ctx.syntax(unit.source())? else {
                incompleteness = incompleteness.combine(Incompleteness::Operational(
                    DerivationExecutionCause::Provider,
                ));
                open = true;
                continue;
            };
            let Some(node) = type_node_for_unit(ctx, &unit, &syntax, &["trait_item"])? else {
                open = true;
                continue;
            };
            let source = syntax.prepared().source();
            let bindings = Bindings::read(ctx, node, source)?;
            if let Some(bounds) = node.child_by_field_name("bounds") {
                for bound in children(bounds) {
                    classify_bound(
                        ctx,
                        unit.source(),
                        source,
                        &bindings,
                        bound,
                        &mut send,
                        &mut sync,
                        &mut open,
                        &mut worklist,
                    )?;
                }
            }
        }
    }
    Ok((send, sync, open, incompleteness))
}

#[allow(clippy::too_many_arguments)]
fn classify_bound(
    ctx: &mut Context<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &Bindings,
    bound: Node<'_>,
    send: &mut bool,
    sync: &mut bool,
    open: &mut bool,
    worklist: &mut Vec<CodeUnit>,
) -> Result<(), MarkerIncomplete> {
    ctx.charge()?;
    if bound.kind() == "lifetime" {
        *open |= text(bound, source) != "'static";
        return Ok(());
    }
    if !matches!(
        bound.kind(),
        "type_identifier" | "scoped_type_identifier" | "generic_type"
    ) {
        *open = true;
        return Ok(());
    }
    let node = head(bound);
    let outcome = ctx.lookup(file, source, node)?;
    match marker(&outcome, node, source, bindings) {
        Some(("Send", _)) => *send = true,
        Some(("Sync", _)) => *sync = true,
        _ if closed_std_bound(&outcome, node, source, bindings) => {}
        _ if outcome.definitions.len() == 1 && outcome.modeled_definitions.is_empty() => {
            worklist.push(outcome.definitions[0].clone());
        }
        _ => *open = true,
    }
    Ok(())
}

fn contains_parameter(
    ctx: &mut Context<'_>,
    node: Node<'_>,
    source: &str,
    parameter: &str,
) -> Result<bool, MarkerIncomplete> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        ctx.charge()?;
        if node.kind() == "type_identifier" && text(node, source) == parameter {
            return Ok(true);
        }
        stack.extend(children(node));
    }
    Ok(false)
}

fn field_uses(
    ctx: &mut Context<'_>,
    file: &ProjectFile,
    declaration: Node<'_>,
    source: &str,
    bindings: &Bindings,
    parameter: &str,
) -> Result<(Vec<CodeQueryRustMarkerUse>, bool), MarkerIncomplete> {
    let mut fields = Vec::new();
    let mut stack = vec![(declaration, String::new())];
    while let Some((node, variant)) = stack.pop() {
        ctx.charge()?;
        match node.kind() {
            "field_declaration" => {
                fields.push((
                    format!(
                        "{variant}{}",
                        text(
                            node.child_by_field_name("name").expect("named field name"),
                            source
                        )
                    ),
                    node.child_by_field_name("type").expect("field type"),
                ));
            }
            "ordered_field_declaration_list" => {
                let mut cursor = node.walk();
                for (ordinal, ty) in node.children_by_field_name("type", &mut cursor).enumerate() {
                    fields.push((format!("{variant}{ordinal}"), ty));
                }
            }
            "enum_variant" => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push((
                        body,
                        format!(
                            "{}.",
                            text(
                                node.child_by_field_name("name").expect("variant name"),
                                source
                            )
                        ),
                    ));
                }
            }
            // Do not descend into expressions or discriminants looking for fields.
            "struct_item" | "enum_item" | "union_item" => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push((body, variant));
                }
            }
            "field_declaration_list" | "enum_variant_list" => {
                for child in children(node) {
                    stack.push((child, variant.clone()));
                }
            }
            _ => {}
        }
    }
    fields.sort_by_key(|(_, node)| node.start_byte());
    let mut uses = Vec::new();
    let mut open = false;
    for (field, ty) in fields {
        let mut stack = vec![(ty, Vec::<String>::new())];
        while let Some((node, mut wrappers)) = stack.pop() {
            ctx.charge()?;
            if node.is_error() || node.is_missing() || node.kind() == "macro_invocation" {
                open = true;
            }
            if node.kind() == "type_identifier" && text(node, source) == parameter {
                uses.push(CodeQueryRustMarkerUse {
                    field: field.clone(),
                    wrappers,
                });
                continue;
            }
            let wrapper = match node.kind() {
                "generic_type" => {
                    let h = head(node);
                    let outcome = ctx.lookup(file, source, h)?;
                    Some(
                        if marker(&outcome, h, source, bindings)
                            .is_some_and(|(name, _)| name == "PhantomData")
                        {
                            "phantom".to_owned()
                        } else {
                            format!("generic:{}", path(h, source).join("::"))
                        },
                    )
                }
                "reference_type" => Some(
                    if children(node)
                        .iter()
                        .any(|n| n.kind() == "mutable_specifier")
                    {
                        "ref_mut"
                    } else {
                        "ref"
                    }
                    .into(),
                ),
                "pointer_type" => Some(
                    if children(node)
                        .iter()
                        .any(|n| n.kind() == "mutable_specifier")
                    {
                        "ptr_mut"
                    } else {
                        "ptr_const"
                    }
                    .into(),
                ),
                "function_type" => Some("fn".into()),
                "dynamic_type" | "abstract_type" => Some("dyn".into()),
                "tuple_type" => Some("tuple".into()),
                "array_type" => Some("array".into()),
                _ => None,
            };
            if let Some(wrapper) = wrapper {
                wrappers.push(wrapper);
            }
            // A generic head names a constructor, not a stored parameter.
            let nested = if node.kind() == "generic_type" {
                children(
                    node.child_by_field_name("type_arguments")
                        .expect("generic arguments"),
                )
            } else {
                children(node)
            };
            for child in nested.into_iter().rev() {
                stack.push((child, wrappers.clone()));
            }
        }
    }
    Ok((uses, open))
}

// Summaries retain names and values, never tree-sitter nodes, and die with the query.
#[derive(Default)]
struct MethodInventory {
    names: HashSet<String>,
    methods: Vec<MethodAccess>,
    reasons: Vec<MarkerIncomplete>,
}

struct MethodAccess {
    shared: bool,
    fields: HashSet<String>,
    calls: HashSet<String>,
    escapes: bool,
}

fn mutable_reference(node: Node<'_>) -> bool {
    node.kind() == "reference_type"
        && children(node)
            .iter()
            .any(|n| n.kind() == "mutable_specifier")
}

fn exclusive_receiver(node: Node<'_>, source: &str) -> bool {
    if mutable_reference(node) {
        return true;
    }
    if node.kind() != "generic_type" {
        return false;
    }
    let arguments = node
        .child_by_field_name("type_arguments")
        .map(children)
        .unwrap_or_default();
    let [argument] = arguments.as_slice() else {
        return false;
    };
    match path(head(node), source).last().map(String::as_str) {
        Some("Box") => argument.kind() == "type_identifier" && text(*argument, source) == "Self",
        Some("Pin") => {
            mutable_reference(*argument)
                && argument
                    .child_by_field_name("type")
                    .is_some_and(|n| n.kind() == "type_identifier" && text(n, source) == "Self")
        }
        _ => false,
    }
}

fn method_access(
    ctx: &mut Context<'_>,
    function: Node<'_>,
    source: &str,
    declaration: &CodeUnit,
) -> Result<MethodAccess, MarkerIncomplete> {
    let mut owner = function.parent();
    while owner.is_some_and(|n| n.kind() != "impl_item") {
        ctx.charge()?;
        owner = owner.and_then(|n| n.parent());
    }
    let reference_impl = owner
        .and_then(|n| n.child_by_field_name("type"))
        .is_some_and(|n| n.kind() == "reference_type");
    let mut receivers = HashSet::default();
    let mut destructured = false;
    let parameters = function
        .child_by_field_name("parameters")
        .map(children)
        .unwrap_or_default();
    for parameter in parameters {
        ctx.charge()?;
        if parameter.kind() == "self_parameter" {
            let mut cursor = parameter.walk();
            let borrowed = parameter.children(&mut cursor).any(|n| n.kind() == "&");
            let mutable = children(parameter)
                .iter()
                .any(|n| n.kind() == "mutable_specifier");
            if reference_impl || (borrowed && !mutable) {
                receivers.insert("self".to_owned());
            }
        } else if parameter.kind() == "parameter"
            && let (Some(pattern), Some(ty)) = (
                parameter.child_by_field_name("pattern"),
                parameter.child_by_field_name("type"),
            )
        {
            if pattern.kind() == "self" {
                if reference_impl || !exclusive_receiver(ty, source) {
                    receivers.insert("self".to_owned());
                }
            } else if ty.kind() == "reference_type"
                && !mutable_reference(ty)
                && ty.child_by_field_name("type").is_some_and(|n| {
                    path(head(n), source)
                        .last()
                        .is_some_and(|name| name == "Self" || name == declaration.terminal_name())
                })
            {
                if pattern.kind() == "identifier" {
                    receivers.insert(text(pattern, source).to_owned());
                } else if pattern.kind() != "_" {
                    // Destructuring the shared argument exposes its values.
                    destructured = true;
                }
            }
        }
    }
    let mut access = MethodAccess {
        shared: destructured || !receivers.is_empty(),
        fields: HashSet::default(),
        calls: HashSet::default(),
        escapes: destructured,
    };
    if !access.shared {
        return Ok(access);
    }
    let body = function
        .child_by_field_name("body")
        .ok_or("Rust shared method body unavailable")?;
    // Carry closure/macro context explicitly; a capture is an escape even if
    // its immediate parent is an otherwise harmless field projection.
    let mut stack = vec![(body, false)];
    while let Some((node, captured)) = stack.pop() {
        ctx.charge()?;
        if node.is_error() || node.is_missing() {
            return Err("Rust shared method contains unavailable syntax".into());
        }
        let captured = captured || matches!(node.kind(), "closure_expression" | "macro_invocation");
        if matches!(node.kind(), "self" | "identifier") && receivers.contains(text(node, source)) {
            if captured {
                access.escapes = true;
            } else if let Some(parent) = node.parent()
                && parent.kind() == "field_expression"
                && parent.child_by_field_name("value") == Some(node)
            {
                let field = parent
                    .child_by_field_name("field")
                    .expect("field expression member");
                let callable = parent
                    .parent()
                    .filter(|n| n.kind() == "generic_function")
                    .filter(|n| n.child_by_field_name("function") == Some(parent))
                    .unwrap_or(parent);
                if callable.parent().is_some_and(|call| {
                    call.kind() == "call_expression"
                        && call.child_by_field_name("function") == Some(callable)
                }) {
                    access.calls.insert(text(field, source).to_owned());
                } else {
                    access.fields.insert(text(field, source).to_owned());
                }
            } else {
                access.escapes = true;
            }
        }
        stack.extend(children(node).into_iter().map(|child| (child, captured)));
    }
    Ok(access)
}

fn method_inventory(ctx: &mut Context<'_>, declaration: &CodeUnit) -> MethodInventory {
    let mut inventory = MethodInventory::default();
    for method in ctx
        .analyzer
        .direct_children(declaration)
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Function)
    {
        inventory.names.insert(method.terminal_name().to_owned());
        let outcome = (|| {
            let syntax = ctx
                .syntax(method.source())?
                .ok_or("Rust method source syntax unavailable")?;
            let source = syntax.prepared().source();
            let ranges = ctx.analyzer.ranges_of(&method);
            let mut found = false;
            let mut stack = vec![syntax.prepared().tree().root_node()];
            while let Some(node) = stack.pop() {
                ctx.charge()?;
                if node.kind() == "function_item"
                    && node
                        .child_by_field_name("name")
                        .is_some_and(|n| text(n, source) == method.terminal_name())
                    && ranges
                        .iter()
                        .any(|r| r.start_byte <= node.start_byte() && r.end_byte >= node.end_byte())
                {
                    found = true;
                    inventory
                        .methods
                        .push(method_access(ctx, node, source, declaration)?);
                } else {
                    stack.extend(children(node).into_iter().filter(|n| {
                        ranges
                            .iter()
                            .any(|r| r.start_byte < n.end_byte() && r.end_byte > n.start_byte())
                    }));
                }
            }
            if found {
                Ok(())
            } else {
                Err(MarkerIncomplete::from(
                    "Rust method function syntax unavailable",
                ))
            }
        })();
        if let Err(reason) = outcome {
            inventory.reasons.push(MarkerIncomplete {
                message: format!("{}: {}", method.fq_name_str(), reason.message),
                incompleteness: reason.incompleteness,
            });
        }
    }
    inventory
}

impl MethodInventory {
    fn shared_access(&self, uses: &[&CodeQueryRustMarkerUse]) -> &'static str {
        let mut worklist = self
            .methods
            .iter()
            .enumerate()
            .filter(|(_, m)| m.shared)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let mut visited = HashSet::default();
        while let Some(index) = worklist.pop() {
            if !visited.insert(index) {
                continue;
            }
            let method = &self.methods[index];
            if method.escapes || uses.iter().any(|u| method.fields.contains(&u.field)) {
                return "touches";
            }
            for call in &method.calls {
                if !self.names.contains(call) {
                    return "touches";
                }
            }
        }
        if self.reasons.is_empty() {
            "none"
        } else {
            "unknown"
        }
    }
}

fn rust_marker_impls(
    analyzer: &dyn IAnalyzer,
    cache: &mut RustMarkerImplsCache,
    declaration: &CodeUnit,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<RustMarkerImplsResult, MarkerIncomplete> {
    let RustMarkerImplsCache {
        syntax,
        files,
        methods,
    } = cache;
    let attribution = memo_attribution(analyzer);
    syntax.read_mut(&attribution, |syntax| {
        files.read_mut(&attribution, |files| {
            methods.read_mut(&attribution, |methods| {
                let revision = analyzer.workspace_content_identity();
                let mut ctx = Context {
                    analyzer,
                    syntax_memo: syntax,
                    revision,
                    budget,
                    limits,
                    cancellation,
                };
                let file = declaration.source();
                let mut result = RustMarkerImplsResult {
                    incompleteness: Incompleteness::Content,
                    rows: Vec::new(),
                    reasons: Vec::new(),
                };
                if crate::analyzer::common::language_for_file(file) != Language::Rust {
                    return Ok(result);
                }
                let key = (file.clone(), revision);
                let prepared = files
                    .entry(key)
                    .or_insert_with(|| MarkerImplFile::read(&mut ctx, file))
                    .as_ref()
                    .map_err(Clone::clone)?;
                let syntax = &prepared.syntax;
                let source = syntax.prepared().source();
                let bindings = &prepared.bindings;
                let mut matching = Vec::new();
                for candidate in &prepared.candidates {
                    ctx.charge()?;
                    let self_outcome = &candidate.self_outcome;
                    let self_proof = if self_outcome.definitions.as_slice()
                        == std::slice::from_ref(declaration)
                    {
                        "resolved"
                    } else if self_outcome.definitions.is_empty()
                        && self_outcome.modeled_definitions.is_empty()
                        && candidate.self_name.as_deref() == Some(declaration.terminal_name())
                        && bindings.types.get(declaration.terminal_name()) == Some(&1)
                    {
                        "name_in_file"
                    } else {
                        continue;
                    };
                    matching.push((candidate, self_proof));
                }
                if matching.is_empty() {
                    return Ok(result);
                }
                let Some(item) = type_node_for_unit(
                    &mut ctx,
                    declaration,
                    syntax,
                    &["struct_item", "enum_item", "union_item"],
                )?
                else {
                    return Ok(result);
                };
                let declaration_bindings = Bindings::read(&mut ctx, item, source)?;
                let declaration_parameters = item
                    .child_by_field_name("type_parameters")
                    .map(children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|n| n.kind() != "lifetime_parameter")
                    .collect::<Vec<_>>();
                for (candidate, self_proof) in matching {
                    let node = syntax
                        .prepared()
                        .tree()
                        .root_node()
                        .descendant_for_byte_range(candidate.span.start, candidate.span.end)
                        .expect("candidate impl belongs to retained syntax");
                    assert_eq!(node.kind(), "impl_item");
                    let impl_bindings = Bindings::read(&mut ctx, node, source)?;
                    let marker_name = candidate.marker_name;
                    let trait_proof = candidate.trait_proof;
                    let self_type = node.child_by_field_name("type").expect("impl self type");
                    let impl_parameters = node
                        .child_by_field_name("type_parameters")
                        .map(children)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|n| n.kind() == "type_parameter")
                        .collect::<Vec<_>>();
                    let arguments = self_type
                        .child_by_field_name("type_arguments")
                        .map(children)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|n| n.kind() != "lifetime")
                        .collect::<Vec<_>>();
                    let impl_keyword = {
                        let mut cursor = node.walk();
                        node.children(&mut cursor)
                            .find(|n| n.kind() == "impl")
                            .expect("impl keyword")
                    };
                    let span = impl_keyword.start_byte()..self_type.end_byte();
                    let range = super::render::range_for_offsets(
                        source,
                        syntax.prepared().line_starts(),
                        span.start,
                        span.end,
                    );
                    let parameters = if impl_parameters.is_empty() {
                        vec![None]
                    } else {
                        impl_parameters.into_iter().map(Some).collect()
                    };
                    for parameter in parameters {
                        let name = parameter.map(|n| {
                            text(
                                n.child_by_field_name("name").expect("type parameter name"),
                                source,
                            )
                        });
                        let positions = arguments
                            .iter()
                            .enumerate()
                            .filter(|(_, arg)| {
                                arg.kind() == "type_identifier" && name == Some(text(**arg, source))
                            })
                            .map(|(i, _)| i)
                            .collect::<Vec<_>>();
                        let mapping_open = name.is_some()
                            && (positions.len() != 1
                                || positions.iter().any(|&i| {
                                    declaration_parameters
                                        .get(i)
                                        .is_none_or(|n| n.kind() != "type_parameter")
                                }));
                        let ordinal = positions.first().copied().filter(|_| !mapping_open);
                        let mapped_name = ordinal
                            .and_then(|i| declaration_parameters[i].child_by_field_name("name"))
                            .map(|n| text(n, source));
                        let (uses, uses_open) = field_uses(
                            &mut ctx,
                            file,
                            item,
                            source,
                            &declaration_bindings,
                            mapped_name.unwrap_or(""),
                        )?;
                        let stored_uses = uses
                            .iter()
                            .filter(|u| !u.wrappers.iter().any(|w| w == "phantom" || w == "fn"))
                            .collect::<Vec<_>>();
                        let stored = !stored_uses.is_empty();
                        let shared_ref_only = stored_uses
                            .iter()
                            .all(|u| u.wrappers.first().is_some_and(|w| w == "ref"));
                        let mut bounds = parameter
                            .and_then(|n| n.child_by_field_name("bounds"))
                            .map(children)
                            .unwrap_or_default();
                        let mut where_open = false;
                        if let Some(name) = name {
                            for clause in children(node)
                                .into_iter()
                                .filter(|n| n.kind() == "where_clause")
                            {
                                for predicate in children(clause)
                                    .into_iter()
                                    .filter(|n| n.kind() == "where_predicate")
                                {
                                    let left =
                                        predicate.child_by_field_name("left").expect("where left");
                                    if left.kind() == "type_identifier"
                                        && text(left, source) == name
                                    {
                                        bounds.extend(children(
                                            predicate
                                                .child_by_field_name("bounds")
                                                .expect("where bounds"),
                                        ));
                                    } else if contains_parameter(&mut ctx, left, source, name)? {
                                        where_open = true;
                                    }
                                }
                            }
                        }
                        let (has_send_bound, has_sync_bound, bounds_open, bounds_incompleteness) =
                            marker_bounds(&mut ctx, file, source, &impl_bindings, &bounds)?;
                        result.incompleteness =
                            result.incompleteness.combine(bounds_incompleteness);
                        let shared_access = if marker_name == "Send" {
                            "not_applicable"
                        } else if mapping_open || uses_open || stored {
                            "unknown"
                        } else {
                            "none"
                        };
                        let complete = !mapping_open && !uses_open && !where_open && !bounds_open;
                        if !complete {
                            result.reasons.push(format!(
                                "incomplete Rust marker impl {} at {} parameter {name:?}",
                                declaration.fq_name_str(),
                                span.start
                            ));
                        }
                        let id = format!(
                            "rust-marker-impl:{}:{}:{}:{name:?}",
                            file.rel_path().display(),
                            syntax
                                .prepared()
                                .source_sha256()
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>(),
                            span.start
                        );
                        result.rows.push(RustMarkerImplValue {
                            file: file.clone(),
                            byte_span: span.clone(),
                            row: CodeQueryRustMarkerImpl {
                                id,
                                path: file.rel_path().to_string_lossy().replace('\\', "/"),
                                language: "rust",
                                range,
                                impl_range: range,
                                trait_kind: if marker_name == "Send" {
                                    "send"
                                } else {
                                    "sync"
                                },
                                trait_proof,
                                self_proof,
                                impl_coverage: "same_file",
                                parameter: name.map(str::to_owned),
                                declaration_parameter_ordinal: ordinal.map(|i| i as u64),
                                mapping_proof: if mapping_open { "open" } else { "position" },
                                has_send_bound,
                                has_sync_bound,
                                bounds: bounds
                                    .into_iter()
                                    .map(|n| text(n, source).to_owned())
                                    .collect(),
                                bounds_proof: if bounds_open || where_open {
                                    "open"
                                } else {
                                    "closed"
                                },
                                stored,
                                shared_ref_only,
                                shared_access,
                                uses,
                                uses_proof: if uses_open { "open" } else { "closed" },
                                completeness: if complete { "complete" } else { "incomplete" },
                            },
                        });
                    }
                }
                // Assemble base facts first: exhausting method syntax work must leave
                // these rows available with unknown access, including multi-parameter impls.
                if result
                    .rows
                    .iter()
                    .any(|value| value.row.trait_kind == "sync" && value.row.stored)
                {
                    let methods = methods
                        .entry(declaration.clone())
                        .or_insert_with(|| method_inventory(&mut ctx, declaration));
                    for reason in &methods.reasons {
                        result.incompleteness =
                            result.incompleteness.combine(reason.incompleteness);
                        result.reasons.push(reason.message.clone());
                    }
                    for value in &mut result.rows {
                        let row = &mut value.row;
                        if row.trait_kind == "sync"
                            && row.stored
                            && row.mapping_proof != "open"
                            && row.uses_proof != "open"
                        {
                            let uses = row
                                .uses
                                .iter()
                                .filter(|u| !u.wrappers.iter().any(|w| w == "phantom" || w == "fn"))
                                .collect::<Vec<_>>();
                            row.shared_access = methods.shared_access(&uses);
                        }
                    }
                }
                Ok(result)
            })
        })
    })
}

pub(super) fn expansions(
    analyzer: &dyn IAnalyzer,
    cache: &mut RustMarkerImplsCache,
    declaration: &CodeUnit,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let uncancelled = CancellationToken::default();
    let outcome = rust_marker_impls(
        analyzer,
        cache,
        declaration,
        budget,
        limits,
        cancellation.unwrap_or(&uncancelled),
    );
    let (rows, reasons, incompleteness) = match outcome {
        Ok(result) => (result.rows, result.reasons, result.incompleteness),
        Err(reason) => (Vec::new(), vec![reason.message], reason.incompleteness),
    };
    if !reasons.is_empty() {
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness,
            related: Vec::new(),
            code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            message: format!("Rust marker impl analysis incomplete: {reasons:?}"),
            branch: Vec::new(),
            language: "rust",
            source: None,
            exhausted_roots: Vec::new(),
            withheld_rows_path: Some(
                declaration
                    .source()
                    .rel_path()
                    .to_string_lossy()
                    .replace('\\', "/"),
            ),
        }));
    }
    rows.into_iter()
        .map(Box::new)
        .map(SemanticPipelineValue::RustMarkerImpl)
        .map(PipelineValue::Semantic)
        .map(pipeline_expansion)
        .collect()
}
