//! Every statement in the workspace's production string literals that changes
//! a SQLite schema or a transaction, against an explicit allowlist.
//!
//! The inventory grants a schema loan (`resolution_selection::SchemaLoan`)
//! that lets nested currency checks skip the full TEMP-schema scan. That is
//! sound only if no schema or transaction mutation on the inventory's
//! connection can happen outside a `SchemaMutation` fence. The fence is
//! issued by the inventory; this test is the other half: a new DDL,
//! transaction-control, SAVEPOINT/RELEASE, ATTACH/DETACH or writable PRAGMA
//! literal anywhere in the workspace fails here until someone classifies it.
//!
//! Counts are per file and statement kind. A count that rises, or a file that
//! appears, fails; a count that falls fails too, so a removed site cannot
//! leave stale allowance for a new one.
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

/// Why a statement cannot change the schema of a connection an inventory holds
/// a loan on.
///
/// - `Fenced`: runs on the inventory's connection inside a `SchemaMutation`
///   fence (`begin_schema_mutation`, `with_schema_mutation`,
///   `with_owned_temp_write`, `with_accounted_temp_transaction`,
///   `initialize_accounted_temp_schema`, `begin/end/pause/resume_stage_read`).
/// - `EpochFenced`: a ROLLBACK that follows `end_stage_read`, which fenced the
///   transaction boundary first and advanced `binding_transaction_epoch`.
/// - `Acquisition`: runs on a reader while it is acquired, cleaned up or
///   checked in, before the inventory exists or after its frame ended.
/// - `Derivation`, `OwnConnection`: run on a connection that is never an
///   inventory's. `no_inventory_connection_is_handed_to_a_mutating_off_inventory_function`
///   checks that no call hands an inventory's connection to a function of these
///   files that runs such a statement.
/// - `NotSql`: the literal is a keyword or message, not a statement.
/// - `TestSupport`: the item is gated by `cfg(any(test, feature = "test-support"))`
///   (or a file declared that way). The feature is enabled only through
///   dev-dependencies and the explicit `test-support` feature, never by a
///   shipped build. Such sites are listed under `<file> [test-support]`, apart
///   from the production sites of the same file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    TestSupport,
    Fenced,
    EpochFenced,
    Acquisition,
    Derivation,
    OwnConnection,
    NotSql,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Kind {
    Ddl,
    Transaction,
    Savepoint,
    Attach,
    Pragma,
    Maintenance,
    /// A rusqlite typed API that begins a transaction or savepoint, or writes a pragma.
    Typed,
}

fn classify(statement: &str) -> Option<Kind> {
    use std::sync::OnceLock;
    static PATTERNS: OnceLock<Vec<(Kind, Regex)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        let p = |kind, re: &str| (kind, Regex::new(&format!("(?is)^\\s*(?:{re})")).unwrap());
        vec![
            p(
                Kind::Ddl,
                r"(?:create|drop|alter)\s+(?:(?:temp|temporary|unique|virtual)\s+)*(?:table|view|index|trigger)\b",
            ),
            p(
                Kind::Transaction,
                r"(?:begin(?:\s+(?:deferred|immediate|exclusive|transaction))*|commit(?:\s+transaction)?|end\s+transaction|(?-i:END)(?:\s+TRANSACTION)?|rollback(?:\s+transaction)?)\s*$",
            ),
            p(
                Kind::Savepoint,
                r"(?:savepoint\s+\S+|release\s+(?:savepoint\s+)?\S+|rollback\s+(?:transaction\s+)?to\b.*)\s*$",
            ),
            p(Kind::Attach, r"(?:attach|detach)\s+(?:database\b|[?'\x22:@$])"),
            p(
                Kind::Ddl,
                r"(?:insert\s+(?:or\s+\w+\s+)?into|update|delete\s+from)\s+(?:\w+\.)?sqlite_(?:schema|master|temp_schema|temp_master)\b",
            ),
            p(
                Kind::Pragma,
                r"pragma\s+(?:[\w.]+\s*(?:=|\()|(?:\w+\.)?writable_schema)",
            ),
            p(Kind::Maintenance, r"(?:reindex|vacuum)\b"),
        ]
    });
    patterns
        .iter()
        .find(|(_, re)| re.is_match(statement))
        .map(|(kind, _)| *kind)
}

/// The statement kinds one literal contains, each `;`-separated piece
/// classified on its own, so a savepoint, rollback or ATTACH after a leading
/// CREATE is counted. A literal counts once per kind: a schema file of a
/// thousand CREATEs is one reviewed Ddl site, not a thousand. A CREATE TRIGGER
/// keeps its body's `;` inside it, up to its closing END. SQL comments are
/// removed first, so a comment before a statement does not hide it.
fn statements(literal: &str) -> Vec<Kind> {
    static COMMENT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let comment = COMMENT.get_or_init(|| Regex::new(r"--[^\n]*").unwrap());
    let literal = comment.replace_all(literal, "");
    static TRIGGER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let trigger = TRIGGER.get_or_init(|| {
        Regex::new(r"(?is)^\s*create\s+(?:(?:temp|temporary)\s+)?trigger\b").unwrap()
    });
    let mut kinds = std::collections::BTreeSet::new();
    let mut in_trigger = false;
    for piece in literal.split(';') {
        if in_trigger {
            in_trigger = !piece.trim().eq_ignore_ascii_case("end");
            continue;
        }
        if let Some(kind) = classify(piece) {
            kinds.insert(kind);
            in_trigger = kind == Kind::Ddl && trigger.is_match(piece);
        }
    }
    kinds.into_iter().collect()
}

/// Where an item is compiled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Gate {
    /// In every build, shipped ones included.
    Production,
    /// Only with the `test-support` feature (or cfg(test)).
    TestSupport,
    /// Only under cfg(test) or `#[test]`.
    TestOnly,
}

/// Evaluate a cfg predicate with `test` and `feature = "test-support"` set as
/// given. Any other predicate atom is assumed enabled: that can only widen what
/// the census scans.
fn cfg_holds(meta: &syn::Meta, test: bool, support: bool) -> bool {
    match meta {
        syn::Meta::Path(path) => !path.is_ident("test") || test,
        syn::Meta::NameValue(pair) => {
            if !pair.path.is_ident("feature") {
                return true;
            }
            match &pair.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(name),
                    ..
                }) if name.value() == "test-support" => support,
                _ => true,
            }
        }
        syn::Meta::List(list) => {
            let children = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .map(|children| children.into_iter().collect::<Vec<_>>())
                .unwrap_or_default();
            if list.path.is_ident("all") {
                children.iter().all(|child| cfg_holds(child, test, support))
            } else if list.path.is_ident("any") {
                children.iter().any(|child| cfg_holds(child, test, support))
            } else if list.path.is_ident("not") {
                children
                    .first()
                    .is_none_or(|child| !cfg_holds(child, test, support))
            } else {
                true
            }
        }
    }
}

fn gate(attributes: &[syn::Attribute]) -> Gate {
    attributes
        .iter()
        .map(|attribute| {
            let path = attribute.path();
            if path.is_ident("test") {
                return Gate::TestOnly;
            }
            let Ok(meta) = attribute.parse_args::<syn::Meta>() else {
                return Gate::Production;
            };
            if !path.is_ident("cfg") || cfg_holds(&meta, false, false) {
                Gate::Production
            } else if cfg_holds(&meta, false, true) {
                Gate::TestSupport
            } else {
                Gate::TestOnly
            }
        })
        .max()
        .unwrap_or(Gate::Production)
}

/// Every string literal in a token stream, unescaped by the parser, through
/// nested groups.
fn string_literals(cursor: syn::buffer::Cursor<'_>, out: &mut Vec<String>) {
    let mut cursor = cursor;
    while !cursor.eof() {
        if let Some((literal, next)) = cursor.literal() {
            if let syn::Lit::Str(text) = syn::Lit::new(literal) {
                out.push(text.value());
            }
            cursor = next;
        } else if let Some((inner, _, _, next)) = cursor.any_group() {
            string_literals(inner, out);
            cursor = next;
        } else if let Some((_, next)) = cursor.token_tree() {
            cursor = next;
        } else {
            break;
        }
    }
}

#[derive(Default)]
struct Literals {
    /// Per kind, and whether the site is compiled only with test-support.
    found: BTreeMap<(Kind, bool), usize>,
    sample: BTreeMap<(Kind, bool), String>,
    /// Out-of-line modules gated by cfg(test): (name, #[path] if any).
    test_modules: Vec<(String, Option<String>)>,
    /// Out-of-line modules compiled only with test-support.
    support_modules: Vec<(String, Option<String>)>,
    /// Nesting depth of test-support items being visited.
    support_depth: usize,
    /// Locals bound to `<x>.connection()`.
    connection_locals: std::collections::BTreeSet<String>,
    /// Callees that receive `<x>.connection()` (or such a local) as an argument.
    handoffs: Vec<String>,
    /// The function being visited, innermost last.
    current: Vec<String>,
    /// The type of the `impl` being visited, innermost last.
    impl_types: Vec<String>,
    /// Per function: statements it contains, and the names it calls.
    functions: BTreeMap<String, FnFacts>,
    /// The directory of the file being visited, for `include_str!` paths.
    dir: PathBuf,
}

#[derive(Default)]
struct FnFacts {
    statements: usize,
    calls: std::collections::BTreeSet<String>,
}

const TYPED_APIS: &[&str] = &[
    "transaction",
    "transaction_with_behavior",
    "unchecked_transaction",
    "savepoint",
    "savepoint_with_name",
    "pragma_update",
    "pragma_update_and_check",
    "set_transaction_behavior",
];

fn is_connection_expr(expr: &syn::Expr, locals: &std::collections::BTreeSet<String>) -> bool {
    match expr {
        syn::Expr::Reference(reference) => is_connection_expr(&reference.expr, locals),
        syn::Expr::Paren(paren) => is_connection_expr(&paren.expr, locals),
        syn::Expr::MethodCall(call) => call.method == "connection" && call.args.is_empty(),
        syn::Expr::Path(path) => path
            .path
            .get_ident()
            .is_some_and(|ident| locals.contains(&ident.to_string())),
        _ => false,
    }
}

impl Literals {
    /// `Type::name` for a qualified path (`Self` resolved to the impl's type),
    /// the bare name otherwise.
    fn call_key(&self, path: &syn::Path) -> String {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        match segments.as_slice() {
            [.., owner, name] if owner == "Self" => match self.impl_types.last() {
                Some(owner) => format!("{owner}::{name}"),
                None => name.clone(),
            },
            [.., owner, name] if owner.chars().next().is_some_and(char::is_uppercase) => {
                format!("{owner}::{name}")
            }
            [.., name] => name.clone(),
            [] => String::new(),
        }
    }

    fn in_current_fn(&mut self) -> &mut FnFacts {
        let name = self.current.last().cloned().unwrap_or_default();
        self.functions.entry(name).or_default()
    }

    fn note(&mut self, text: &str) {
        let support = self.support_depth > 0;
        for kind in statements(text) {
            if !support {
                self.in_current_fn().statements += 1;
            }
            *self.found.entry((kind, support)).or_default() += 1;
            self.sample.entry((kind, support)).or_insert_with(|| {
                text.split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(70)
                    .collect()
            });
        }
    }
}

impl<'ast> Visit<'ast> for Literals {
    fn visit_attribute(&mut self, _: &'ast syn::Attribute) {}

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let gate = gate(&item.attrs);
        if gate != Gate::Production {
            if gate == Gate::TestSupport && item.content.is_some() {
                self.support_depth += 1;
                syn::visit::visit_item_mod(self, item);
                self.support_depth -= 1;
            } else if item.content.is_none() {
                let path = item.attrs.iter().find_map(|attribute| {
                    if !attribute.path().is_ident("path") {
                        return None;
                    }
                    match &attribute.meta {
                        syn::Meta::NameValue(syn::MetaNameValue {
                            value:
                                syn::Expr::Lit(syn::ExprLit {
                                    lit: syn::Lit::Str(path),
                                    ..
                                }),
                            ..
                        }) => Some(path.value()),
                        _ => None,
                    }
                });
                if gate == Gate::TestSupport {
                    self.support_modules.push((item.ident.to_string(), path));
                } else {
                    self.test_modules.push((item.ident.to_string(), path));
                }
            }
        } else {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let gate = gate(&item.attrs);
        if gate != Gate::TestOnly {
            self.support_depth += usize::from(gate == Gate::TestSupport);
            self.current.push(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.current.pop();
            self.support_depth -= usize::from(gate == Gate::TestSupport);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&local.pat, &local.init)
            && is_connection_expr(&init.expr, &self.connection_locals)
        {
            self.connection_locals.insert(pattern.ident.to_string());
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let key = self.call_key(&path.path);
            if call
                .args
                .iter()
                .any(|arg| is_connection_expr(arg, &self.connection_locals))
            {
                self.handoffs.push(key.clone());
            }
            self.in_current_fn().calls.insert(key);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if TYPED_APIS.contains(&method.as_str()) {
            let support = self.support_depth > 0;
            *self.found.entry((Kind::Typed, support)).or_default() += 1;
            if !support {
                self.in_current_fn().statements += 1;
            }
            self.sample
                .entry((Kind::Typed, support))
                .or_insert(method.clone());
        }
        if call
            .args
            .iter()
            .any(|arg| is_connection_expr(arg, &self.connection_locals))
        {
            self.handoffs.push(format!("?::{method}"));
        }
        // Only `self.method()` is resolved by name: another receiver's method
        // of the same name is a different function.
        if matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("self")) {
            let key = match self.impl_types.last() {
                Some(owner) => format!("{owner}::{method}"),
                None => method,
            };
            self.in_current_fn().calls.insert(key);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let gate = gate(&item.attrs);
        if gate != Gate::TestOnly {
            self.support_depth += usize::from(gate == Gate::TestSupport);
            let owner = match &*item.self_ty {
                syn::Type::Path(path) => path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default(),
                _ => String::new(),
            };
            self.impl_types.push(owner);
            syn::visit::visit_item_impl(self, item);
            self.impl_types.pop();
            self.support_depth -= usize::from(gate == Gate::TestSupport);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let gate = gate(&item.attrs);
        if gate != Gate::TestOnly {
            self.support_depth += usize::from(gate == Gate::TestSupport);
            let key = match self.impl_types.last() {
                Some(owner) => format!("{owner}::{}", item.sig.ident),
                None => item.sig.ident.to_string(),
            };
            self.current.push(key);
            syn::visit::visit_impl_item_fn(self, item);
            self.current.pop();
            self.support_depth -= usize::from(gate == Gate::TestSupport);
        }
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        let gate = gate(&item.attrs);
        if gate != Gate::TestOnly {
            self.support_depth += usize::from(gate == Gate::TestSupport);
            // Statements in a named SQL constant belong to the constant; a
            // path reference to it is a call edge (visit_expr_path).
            self.current.push(item.ident.to_string());
            syn::visit::visit_item_const(self, item);
            self.current.pop();
            self.support_depth -= usize::from(gate == Gate::TestSupport);
        }
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        let gate = gate(&item.attrs);
        if gate != Gate::TestOnly {
            self.support_depth += usize::from(gate == Gate::TestSupport);
            // Statements in a named SQL constant belong to the constant; a
            // path reference to it is a call edge (visit_expr_path).
            self.current.push(item.ident.to_string());
            syn::visit::visit_item_static(self, item);
            self.current.pop();
            self.support_depth -= usize::from(gate == Gate::TestSupport);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        let key = self.call_key(&path.path);
        if !key.is_empty() {
            self.in_current_fn().calls.insert(key);
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.note(&lit.value());
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        use syn::punctuated::Punctuated;
        // SQL kept in a file is still production SQL of this file.
        if mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "include_str")
            && let Ok(path) = mac.parse_body::<syn::LitStr>()
        {
            let file = self.dir.join(path.value());
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
            self.note(&text);
            return;
        }
        // Format-like macros parse as expressions. Anything else (a
        // macro_rules! body, stringify!) is scanned for its string tokens.
        if let Ok(args) =
            mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        {
            for arg in &args {
                self.visit_expr(arg);
            }
            return;
        }
        let buffer = syn::buffer::TokenBuffer::new2(mac.tokens.clone());
        let mut found = Vec::new();
        string_literals(buffer.begin(), &mut found);
        for text in found {
            self.note(&text);
        }
    }
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" && name != "target" {
                source_files(&path, out);
            }
        } else if name.ends_with(".rs") && name != "build.rs" {
            out.push(path);
        }
    }
}

type Counts = BTreeMap<(String, Kind), usize>;
type Samples = BTreeMap<(String, Kind), String>;

struct Census {
    counts: Counts,
    samples: Samples,
    /// (file, callee) for every call that receives an inventory connection.
    handoffs: Vec<(String, String)>,
    /// Per file, the names of functions that run a schema or transaction
    /// statement, directly or through a call to such a function of the same file.
    mutating_fns: BTreeMap<String, std::collections::BTreeSet<String>>,
}

/// The files and directories a cfg(test) `mod name;` declaration removes.
fn test_gated(file: &Path, modules: &[(String, Option<String>)]) -> Vec<PathBuf> {
    let dir = file.parent().unwrap();
    let stem = file.file_stem().unwrap().to_string_lossy().into_owned();
    let base = if matches!(stem.as_str(), "mod" | "lib" | "main") {
        dir.to_owned()
    } else {
        dir.join(&stem)
    };
    let mut gated = Vec::new();
    for (name, path) in modules {
        match path {
            Some(path) => {
                let target = dir.join(path);
                if let Some(parent) = target.parent() {
                    gated.push(target.clone());
                    if target.file_name().is_some_and(|n| n == "mod.rs") {
                        gated.push(parent.to_owned());
                    }
                }
            }
            None => {
                gated.push(base.join(format!("{name}.rs")));
                gated.push(base.join(name).join("mod.rs"));
                gated.push(base.join(name));
            }
        }
    }
    gated
}

fn mutating(functions: &BTreeMap<String, FnFacts>) -> std::collections::BTreeSet<String> {
    let mut mutating: std::collections::BTreeSet<String> = functions
        .iter()
        .filter(|(name, facts)| !name.is_empty() && facts.statements > 0)
        .map(|(name, _)| name.clone())
        .collect();
    loop {
        let before = mutating.len();
        for (name, facts) in functions {
            if !name.is_empty() && facts.calls.iter().any(|call| mutating.contains(call)) {
                mutating.insert(name.clone());
            }
        }
        if mutating.len() == before {
            return mutating;
        }
    }
}

fn census() -> Census {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            source_files(&src, &mut files);
        }
    }
    let mut visited = Vec::new();
    let mut gated = Vec::new();
    let mut supported = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let Ok(syntax) = syn::parse_file(&text) else {
            panic!("{} does not parse", file.display());
        };
        let mut literals = Literals {
            dir: file.parent().unwrap().to_owned(),
            ..Literals::default()
        };
        literals.visit_file(&syntax);
        gated.extend(test_gated(&file, &literals.test_modules));
        supported.extend(test_gated(&file, &literals.support_modules));
        visited.push((file, literals));
    }
    let mut census = Census {
        counts: BTreeMap::new(),
        samples: BTreeMap::new(),
        handoffs: Vec::new(),
        mutating_fns: BTreeMap::new(),
    };
    for (file, literals) in visited {
        if gated.iter().any(|gate| file.starts_with(gate)) {
            continue;
        }
        let relative = file
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let file_support = supported.iter().any(|gate| file.starts_with(gate));
        // Test-support sites are counted under `<file> [test-support]`.
        let key = |support: bool| {
            if support || file_support {
                format!("{relative} [test-support]")
            } else {
                relative.clone()
            }
        };
        for ((kind, support), count) in literals.found {
            *census.counts.entry((key(support), kind)).or_default() += count;
        }
        for ((kind, support), sample) in literals.sample {
            census.samples.entry((key(support), kind)).or_insert(sample);
        }
        for callee in literals.handoffs {
            census.handoffs.push((relative.clone(), callee));
        }
        census
            .mutating_fns
            .insert(relative, mutating(&literals.functions));
    }
    census
}

#[test]
fn schema_and_transaction_statements_match_the_reviewed_allowlist() {
    let Census {
        counts: actual,
        samples,
        ..
    } = census();
    let allowed = super::schema_mutation_allowlist::ALLOWED
        .iter()
        .map(|(file, kind, count, _class)| ((file.to_string(), *kind), *count))
        .collect::<BTreeMap<_, _>>();
    let mut differences = Vec::new();
    for (key, count) in &actual {
        if allowed.get(key) != Some(count) {
            differences.push(format!(
                "{} {:?}: found {count}, allowed {:?}; first literal {:?}",
                key.0,
                key.1,
                allowed.get(key),
                samples[key]
            ));
        }
    }
    for (key, count) in &allowed {
        if !actual.contains_key(key) {
            differences.push(format!(
                "{} {:?}: allowed {count}, found none",
                key.0, key.1
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "classify each change against the inventory's SchemaMutation fence, \
         then update schema_mutation_allowlist.rs:\n{}",
        differences.join("\n")
    );
}

/// No call hands an inventory's connection to a function that runs a schema or
/// transaction statement in a file classified as off the inventory connection.
/// This follows the connection through calls, which a name check on the file
/// cannot. Names are matched, so a collision is a false alarm to rename or
/// classify; it is never silently accepted.
#[test]
fn no_inventory_connection_is_handed_to_a_mutating_off_inventory_function() {
    let census = census();
    let mut off_inventory: Vec<(&str, &String)> = Vec::new();
    for (file, _, _, class) in super::schema_mutation_allowlist::ALLOWED {
        if matches!(class, Class::Derivation | Class::OwnConnection) {
            for name in census.mutating_fns.get(*file).into_iter().flatten() {
                off_inventory.push((file, name));
            }
        }
    }
    off_inventory.sort();
    off_inventory.dedup();
    assert!(
        !off_inventory.is_empty() && !census.handoffs.is_empty(),
        "the census must see both the helpers and the handoffs it checks"
    );
    // Reviewed handoffs: the callee mutates only TEMP views, idempotently
    // (guarded by `selected_workspace_revisions`), and the caller runs it on
    // the selection connection right before its own TEMP schema batch, which
    // is the fenced mutation of that same connection.
    const REVIEWED_HANDOFFS: &[(&str, &str)] = &[(
        "bifrost-store/src/analyzer/store/resolution_selection.rs",
        "ensure_revisioned_workspace_views",
    )];
    let mut offenders = Vec::new();
    for (caller, callee) in &census.handoffs {
        if REVIEWED_HANDOFFS
            .iter()
            .any(|(file, reviewed)| caller == file && callee == reviewed)
        {
            continue;
        }
        for (file, name) in &off_inventory {
            // `?::m` is a method call on an unknown receiver: any `Type::m`.
            let hit = match callee.strip_prefix("?::") {
                Some(method) => name.rsplit("::").next() == Some(method),
                None => callee == *name,
            };
            if hit {
                offenders.push(format!(
                    "{caller} passes an inventory connection to {callee}, which mutates as {name} in {file}"
                ));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
fn the_census_classifies_what_it_must_not_miss() {
    // A CREATE-led literal still reports a later savepoint or ATTACH.
    assert_eq!(
        statements("CREATE TEMP TABLE t(x); ROLLBACK TO sp"),
        vec![Kind::Ddl, Kind::Savepoint]
    );
    assert_eq!(
        statements("CREATE TEMP TABLE t(x); ATTACH DATABASE ?1 AS other"),
        vec![Kind::Ddl, Kind::Attach]
    );
    // A leading SQL comment does not hide the statement.
    assert_eq!(
        statements("-- why\nCREATE TEMP VIEW v AS SELECT 1"),
        vec![Kind::Ddl]
    );
    // A trigger body's own statements belong to the trigger; what follows
    // its END does not.
    assert_eq!(
        statements("CREATE TEMP TRIGGER g AFTER INSERT ON t BEGIN DELETE FROM t; END; SAVEPOINT s"),
        vec![Kind::Ddl, Kind::Savepoint]
    );
    // Many statements of one kind are one reviewed site.
    assert_eq!(
        statements("CREATE TABLE a(x); CREATE TABLE b(y)"),
        vec![Kind::Ddl]
    );
}

#[test]
fn cfg_gates_follow_the_predicate_not_its_spelling() {
    let gate_of = |source: &str| {
        let item: syn::ItemFn = syn::parse_str(&format!("{source} fn f() {{}}")).unwrap();
        gate(&item.attrs)
    };
    assert_eq!(gate_of("#[cfg(test)]"), Gate::TestOnly);
    assert_eq!(gate_of("#[test]"), Gate::TestOnly);
    assert_eq!(gate_of("#[cfg(not(test))]"), Gate::Production);
    assert_eq!(
        gate_of("#[cfg(any(test, feature = \"test-support\"))]"),
        Gate::TestSupport
    );
    assert_eq!(
        gate_of("#[cfg(any(test, feature = \"other\"))]"),
        Gate::Production
    );
    assert_eq!(
        gate_of("#[cfg(all(test, feature = \"test-support\"))]"),
        Gate::TestOnly
    );
    assert_eq!(gate_of("#[cfg(unix)]"), Gate::Production);
}

#[test]
fn macro_string_literals_are_unescaped_by_the_parser() {
    let mac: syn::Macro = syn::parse_str(r#"m!(a, { "SAVEPOINT \"x\"\n" }, 1)"#).unwrap();
    let buffer = syn::buffer::TokenBuffer::new2(mac.tokens.clone());
    let mut found = Vec::new();
    string_literals(buffer.begin(), &mut found);
    assert_eq!(found, vec!["SAVEPOINT \"x\"\n".to_string()]);
}
