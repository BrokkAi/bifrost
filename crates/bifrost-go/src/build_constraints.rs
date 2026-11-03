//! Go build constraints (#9048).
//!
//! A Go file's build constraint is its `_GOOS`/`_GOARCH` filename suffix and
//! its `//go:build` header directive (or, without one, its legacy `// +build`
//! lines), conjoined. Structure selects the directive comments; the directive
//! text itself is a small expression language over build tags that the Go
//! grammar does not parse, so it is parsed here as the value of that comment.
//!
//! Two questions are answered from it. Under one selected configuration, is
//! the file compiled? And, independent of any host, for which GOOS and GOARCH
//! can the file be compiled at all?

use std::path::Path;

use tree_sitter::Node;

use crate::package_discovery::GoBuildConfiguration;
use crate::packages::{
    KNOWN_GOARCH, KNOWN_GOOS, UNIX_GOOS, goos_satisfies_tag, source_filename_target,
};

/// One parsed build-constraint expression over build tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoBuildExpr {
    Tag(String),
    Not(Box<GoBuildExpr>),
    And(Box<GoBuildExpr>, Box<GoBuildExpr>),
    Or(Box<GoBuildExpr>, Box<GoBuildExpr>),
}

/// Nesting beyond this is refused as invalid, which also bounds the recursive
/// parser and evaluator below.
const MAX_EXPRESSION_DEPTH: usize = 64;

/// Free tags beyond this make the per-target scope unknown instead of
/// enumerating every assignment.
const MAX_FREE_TAGS: usize = 10;

/// The build-constraint directive comments of one file: the leading top-level
/// line comments before the package clause that start `//go:build` or
/// `// +build`. A matching comment inside a block comment or after the package
/// clause cannot constrain the file.
pub fn go_build_constraint_comments<'s>(root: Node<'_>, source: &'s str) -> Vec<&'s str> {
    let mut comments = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "package_clause" {
            break;
        }
        if child.kind() != "comment" {
            continue;
        }
        let comment = &source[child.start_byte()..child.end_byte()];
        if directive_tail(comment, GO_BUILD).is_some()
            || directive_tail(comment, PLUS_BUILD).is_some()
        {
            comments.push(comment);
        }
    }
    comments
}

const GO_BUILD: &str = "//go:build";
const PLUS_BUILD: &str = "// +build";

fn directive_tail<'s>(comment: &'s str, directive: &str) -> Option<&'s str> {
    comment
        .strip_prefix(directive)
        .filter(|tail| tail.chars().next().is_none_or(char::is_whitespace))
}

/// The build constraint of one file: its filename suffix conjoined with its
/// directive. `Ok(None)` means the file is unconstrained; `Err` carries the
/// directive text Go would reject.
pub fn go_file_build_constraint(
    path: &Path,
    directives: &[&str],
) -> Result<Option<GoBuildExpr>, String> {
    let go_build: Vec<&str> = directives
        .iter()
        .filter_map(|comment| directive_tail(comment, GO_BUILD))
        .collect();
    let directive = match go_build.as_slice() {
        [] => {
            let mut lines = None;
            for tail in directives
                .iter()
                .filter_map(|comment| directive_tail(comment, PLUS_BUILD))
            {
                let line = parse_plus_build_line(tail).ok_or_else(|| tail.trim().to_owned())?;
                lines = Some(and_option(lines, line));
            }
            lines
        }
        [tail] => Some(parse_go_build(tail).ok_or_else(|| tail.trim().to_owned())?),
        _ => return Err(go_build.join(" ")),
    };
    let (os, arch) = source_filename_target(path);
    let filename = [os, arch]
        .into_iter()
        .flatten()
        .map(|tag| GoBuildExpr::Tag(tag.to_owned()))
        .reduce(|left, right| GoBuildExpr::And(Box::new(left), Box::new(right)));
    Ok(match (filename, directive) {
        (Some(filename), Some(directive)) => {
            Some(GoBuildExpr::And(Box::new(filename), Box::new(directive)))
        }
        (filename, directive) => filename.or(directive),
    })
}

fn and_option(left: Option<GoBuildExpr>, right: GoBuildExpr) -> GoBuildExpr {
    match left {
        Some(left) => GoBuildExpr::And(Box::new(left), Box::new(right)),
        None => right,
    }
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '.')
}

/// One legacy `// +build` line: space-separated alternatives of
/// comma-separated terms, each an optionally negated tag.
fn parse_plus_build_line(line: &str) -> Option<GoBuildExpr> {
    let mut alternatives = None;
    for field in line.split_whitespace() {
        let mut terms = None;
        for term in field.split(',') {
            let (negated, tag) = match term.strip_prefix('!') {
                Some(tag) => (true, tag),
                None => (false, term),
            };
            if !valid_tag(tag) {
                return None;
            }
            let tag = GoBuildExpr::Tag(tag.to_owned());
            let term = if negated {
                GoBuildExpr::Not(Box::new(tag))
            } else {
                tag
            };
            terms = Some(and_option(terms, term));
        }
        let term = terms?;
        alternatives = Some(match alternatives {
            Some(left) => GoBuildExpr::Or(Box::new(left), Box::new(term)),
            None => term,
        });
    }
    alternatives
}

/// One `//go:build` expression: `||` binds loosest, then `&&`, then `!`.
fn parse_go_build(text: &str) -> Option<GoBuildExpr> {
    let mut tokens = Vec::new();
    let mut rest = text.trim();
    while !rest.is_empty() {
        let token_len = if rest.starts_with("&&") || rest.starts_with("||") {
            2
        } else if rest.starts_with(['!', '(', ')']) {
            1
        } else {
            rest.find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
                .unwrap_or(rest.len())
        };
        if token_len == 0 {
            return None;
        }
        tokens.push(&rest[..token_len]);
        rest = rest[token_len..].trim_start();
    }
    let mut parser = GoBuildParser { tokens, next: 0 };
    let expr = parser.or(0)?;
    (parser.next == parser.tokens.len()).then_some(expr)
}

struct GoBuildParser<'s> {
    tokens: Vec<&'s str>,
    next: usize,
}

impl<'s> GoBuildParser<'s> {
    fn peek(&self) -> Option<&'s str> {
        self.tokens.get(self.next).copied()
    }

    fn or(&mut self, depth: usize) -> Option<GoBuildExpr> {
        let mut left = self.and(depth)?;
        while self.peek() == Some("||") {
            self.next += 1;
            left = GoBuildExpr::Or(Box::new(left), Box::new(self.and(depth)?));
        }
        Some(left)
    }

    fn and(&mut self, depth: usize) -> Option<GoBuildExpr> {
        let mut left = self.not(depth)?;
        while self.peek() == Some("&&") {
            self.next += 1;
            left = GoBuildExpr::And(Box::new(left), Box::new(self.not(depth)?));
        }
        Some(left)
    }

    fn not(&mut self, depth: usize) -> Option<GoBuildExpr> {
        if self.peek() == Some("!") {
            self.next += 1;
            // Go rejects a double negation.
            if self.peek() == Some("!") {
                return None;
            }
            return Some(GoBuildExpr::Not(Box::new(self.atom(depth)?)));
        }
        self.atom(depth)
    }

    fn atom(&mut self, depth: usize) -> Option<GoBuildExpr> {
        let token = self.peek()?;
        self.next += 1;
        if token == "(" {
            if depth >= MAX_EXPRESSION_DEPTH {
                return None;
            }
            let expr = self.or(depth + 1)?;
            if self.peek() != Some(")") {
                return None;
            }
            self.next += 1;
            return Some(expr);
        }
        valid_tag(token).then(|| GoBuildExpr::Tag(token.to_owned()))
    }
}

impl GoBuildExpr {
    /// Kleene evaluation: `None` from a tag is unknown and stays unknown
    /// unless the other operand decides the result.
    pub fn eval(&self, tag: &mut impl FnMut(&str) -> Option<bool>) -> Option<bool> {
        match self {
            Self::Tag(name) => tag(name),
            Self::Not(inner) => inner.eval(tag).map(|value| !value),
            Self::And(left, right) => match (left.eval(tag), right.eval(tag)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            Self::Or(left, right) => match (left.eval(tag), right.eval(tag)) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
        }
    }

    fn tags<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::Tag(name) => {
                if !out.contains(&name.as_str()) {
                    out.push(name);
                }
            }
            Self::Not(inner) => inner.tags(out),
            Self::And(left, right) | Self::Or(left, right) => {
                left.tags(out);
                right.tags(out);
            }
        }
    }

    /// The canonical `//go:build` spelling, with only the parentheses the
    /// operator precedence requires.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out, 0);
        out
    }

    /// `level` is the binding strength the context requires: 0 for `||`,
    /// 1 for `&&`, 2 for an operand of `!`.
    fn render_into(&self, out: &mut String, level: u8) {
        let (own, separator) = match self {
            Self::Tag(name) => {
                out.push_str(name);
                return;
            }
            Self::Not(inner) => {
                out.push('!');
                inner.render_into(out, 2);
                return;
            }
            Self::And(..) => (1, " && "),
            Self::Or(..) => (0, " || "),
        };
        let (Self::And(left, right) | Self::Or(left, right)) = self else {
            unreachable!("binary operators only")
        };
        let parenthesize = own < level;
        if parenthesize {
            out.push('(');
        }
        // Both operators are associative, so an operand of the same operator
        // needs no parentheses on either side.
        left.render_into(out, own);
        out.push_str(separator);
        right.render_into(out, own);
        if parenthesize {
            out.push(')');
        }
    }
}

/// The value of one build tag when building for `build`, as `go/build`
/// matches it. Release (`go1.N`) and experiment tags depend on the toolchain
/// version, which the selected configuration does not fix, so they are unknown.
pub fn go_tag_under(build: &GoBuildConfiguration, tag: &str) -> Option<bool> {
    if goos_satisfies_tag(&build.goos, tag) || tag == build.goarch {
        return Some(true);
    }
    match tag {
        "unix" => Some(UNIX_GOOS.contains(&build.goos.as_str())),
        "cgo" => Some(build.cgo_enabled),
        "gc" => Some(true),
        "gccgo" => Some(false),
        _ if build.tags.iter().any(|selected| selected == tag) => Some(true),
        _ if tag.starts_with("go1.") || tag.starts_with("goexperiment.") => None,
        _ => Some(false),
    }
}

/// The set of target values one axis admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoTargetScope {
    /// Every known value: the constraint does not restrict this axis.
    Any,
    /// Exactly these known values, in the order of the known-value table.
    /// Empty when no target satisfies the constraint.
    Only(Vec<&'static str>),
    /// The constraint is invalid or too large to enumerate.
    Unknown,
}

/// For which GOOS and for which GOARCH the constraint can be satisfied by some
/// choice of every other tag. This depends on the file alone, never on the host
/// or the selected configuration.
pub fn go_target_scopes(
    constraint: &Result<Option<GoBuildExpr>, String>,
) -> (GoTargetScope, GoTargetScope) {
    let expr = match constraint {
        Ok(None) => return (GoTargetScope::Any, GoTargetScope::Any),
        Ok(Some(expr)) => expr,
        Err(_) => return (GoTargetScope::Unknown, GoTargetScope::Unknown),
    };
    let mut tags = Vec::new();
    expr.tags(&mut tags);
    let free: Vec<&str> = tags
        .into_iter()
        .filter(|tag| *tag != "unix" && !KNOWN_GOOS.contains(tag) && !KNOWN_GOARCH.contains(tag))
        .collect();
    if free.len() > MAX_FREE_TAGS {
        return (GoTargetScope::Unknown, GoTargetScope::Unknown);
    }
    let mut os_admitted = vec![false; KNOWN_GOOS.len()];
    let mut arch_admitted = vec![false; KNOWN_GOARCH.len()];
    for (os_index, goos) in KNOWN_GOOS.iter().enumerate() {
        for (arch_index, goarch) in KNOWN_GOARCH.iter().enumerate() {
            if os_admitted[os_index] && arch_admitted[arch_index] {
                continue;
            }
            let satisfiable = (0..1_u32 << free.len()).any(|assignment| {
                let mut value = |tag: &str| {
                    Some(
                        if let Some(bit) = free.iter().position(|free| *free == tag) {
                            assignment & (1 << bit) != 0
                        } else if tag == "unix" {
                            UNIX_GOOS.contains(goos)
                        } else if KNOWN_GOOS.contains(&tag) {
                            goos_satisfies_tag(goos, tag)
                        } else {
                            tag == *goarch
                        },
                    )
                };
                expr.eval(&mut value) == Some(true)
            });
            if satisfiable {
                os_admitted[os_index] = true;
                arch_admitted[arch_index] = true;
            }
        }
    }
    let scope = |known: &[&'static str], admitted: &[bool]| {
        if admitted.iter().all(|admitted| *admitted) {
            GoTargetScope::Any
        } else {
            GoTargetScope::Only(
                known
                    .iter()
                    .zip(admitted)
                    .filter_map(|(value, admitted)| admitted.then_some(*value))
                    .collect(),
            )
        }
    };
    (
        scope(KNOWN_GOOS, &os_admitted),
        scope(KNOWN_GOARCH, &arch_admitted),
    )
}
