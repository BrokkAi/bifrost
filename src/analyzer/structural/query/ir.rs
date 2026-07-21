use super::super::kinds::{NormalizedKind, Role};
use super::schema::{CodeQueryExecutionMode, QueryStepOp};
use crate::analyzer::Language;
use crate::analyzer::usages::{ReferenceKind, UsageHitSurface, UsageProof};
use regex::Regex;
use std::fmt;
use std::num::NonZeroUsize;

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
pub const MAX_WHERE_GLOBS: usize = 128;
pub const MAX_GLOB_LENGTH: usize = 1024;
pub const MAX_LANGUAGE_FILTERS: usize = 32;
pub const MAX_PATTERN_DEPTH: usize = 64;
pub const MAX_PATTERN_NODES: usize = 256;
pub const MAX_KIND_LIST_ENTRIES: usize = 32;
pub const MAX_ROLE_LIST_ENTRIES: usize = 64;
pub const MAX_KWARGS: usize = 64;
pub const MAX_STRING_PREDICATE_LENGTH: usize = 4096;
pub const MAX_CAPTURE_LENGTH: usize = 128;
pub const MAX_KWARG_NAME_LENGTH: usize = 128;
pub const MAX_QUERY_STEPS: usize = 16;
pub const MAX_QUERY_BRANCHES: usize = 16;
pub const MAX_QUERY_PLAN_DEPTH: usize = 16;
pub const MAX_QUERY_PLAN_NODES: usize = 64;
pub const SCHEMA_VERSION: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryValueKind {
    StructuralMatch,
    Declaration,
    ReferenceSite,
    CallSite,
    ExpressionSite,
    ReceiverAnalysis,
    File,
}

impl QueryValueKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::StructuralMatch => "structural_match",
            Self::Declaration => "declaration",
            Self::ReferenceSite => "reference_site",
            Self::CallSite => "call_site",
            Self::ExpressionSite => "expression_site",
            Self::ReceiverAnalysis => "receiver_analysis",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReferenceTraversalFilter {
    pub reference_kinds: Vec<ReferenceKind>,
    pub proof: Option<UsageProof>,
    pub surface: UsageHitSurface,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallTraversalFilter {
    pub depth: NonZeroUsize,
    pub proof: Option<UsageProof>,
}

impl Default for CallTraversalFilter {
    fn default() -> Self {
        Self {
            depth: NonZeroUsize::MIN,
            proof: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallSiteTraversalFilter {
    pub proof: Option<UsageProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiverTraversalFilter {
    pub capture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallInputSelector {
    Receiver,
    ParameterIndex(usize),
    ParameterName(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyTraversal {
    Direct,
    Depth(NonZeroUsize),
    Transitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStep {
    EnclosingDecl,
    FileOf,
    ImportsOf,
    ImportersOf,
    Supertypes(HierarchyTraversal),
    Subtypes(HierarchyTraversal),
    Members,
    Owner,
    ReferencesOf(ReferenceTraversalFilter),
    UsedBy(ReferenceTraversalFilter),
    Uses(ReferenceTraversalFilter),
    Callers(CallTraversalFilter),
    Callees(CallTraversalFilter),
    CallSitesTo(CallSiteTraversalFilter),
    CallSitesFrom(CallSiteTraversalFilter),
    CallInput(CallInputSelector),
    ReceiverTargets(ReceiverTraversalFilter),
    PointsTo(ReceiverTraversalFilter),
    MemberTargets(ReceiverTraversalFilter),
}

impl QueryStep {
    pub fn label(&self) -> &'static str {
        self.op().label()
    }

    pub fn op(&self) -> QueryStepOp {
        match self {
            Self::EnclosingDecl => QueryStepOp::EnclosingDecl,
            Self::FileOf => QueryStepOp::FileOf,
            Self::ImportsOf => QueryStepOp::ImportsOf,
            Self::ImportersOf => QueryStepOp::ImportersOf,
            Self::Supertypes(_) => QueryStepOp::Supertypes,
            Self::Subtypes(_) => QueryStepOp::Subtypes,
            Self::Members => QueryStepOp::Members,
            Self::Owner => QueryStepOp::Owner,
            Self::ReferencesOf(_) => QueryStepOp::ReferencesOf,
            Self::UsedBy(_) => QueryStepOp::UsedBy,
            Self::Uses(_) => QueryStepOp::Uses,
            Self::Callers(_) => QueryStepOp::Callers,
            Self::Callees(_) => QueryStepOp::Callees,
            Self::CallSitesTo(_) => QueryStepOp::CallSitesTo,
            Self::CallSitesFrom(_) => QueryStepOp::CallSitesFrom,
            Self::CallInput(_) => QueryStepOp::CallInput,
            Self::ReceiverTargets(_) => QueryStepOp::ReceiverTargets,
            Self::PointsTo(_) => QueryStepOp::PointsTo,
            Self::MemberTargets(_) => QueryStepOp::MemberTargets,
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match QueryStepOp::from_label(label)? {
            QueryStepOp::EnclosingDecl => Some(Self::EnclosingDecl),
            QueryStepOp::FileOf => Some(Self::FileOf),
            QueryStepOp::ImportsOf => Some(Self::ImportsOf),
            QueryStepOp::ImportersOf => Some(Self::ImportersOf),
            QueryStepOp::Supertypes => Some(Self::Supertypes(HierarchyTraversal::Direct)),
            QueryStepOp::Subtypes => Some(Self::Subtypes(HierarchyTraversal::Direct)),
            QueryStepOp::Members => Some(Self::Members),
            QueryStepOp::Owner => Some(Self::Owner),
            QueryStepOp::ReferencesOf => {
                Some(Self::ReferencesOf(ReferenceTraversalFilter::default()))
            }
            QueryStepOp::UsedBy => Some(Self::UsedBy(ReferenceTraversalFilter::default())),
            QueryStepOp::Uses => Some(Self::Uses(ReferenceTraversalFilter::default())),
            QueryStepOp::Callers => Some(Self::Callers(CallTraversalFilter::default())),
            QueryStepOp::Callees => Some(Self::Callees(CallTraversalFilter::default())),
            QueryStepOp::CallSitesTo => Some(Self::CallSitesTo(CallSiteTraversalFilter::default())),
            QueryStepOp::CallSitesFrom => {
                Some(Self::CallSitesFrom(CallSiteTraversalFilter::default()))
            }
            QueryStepOp::CallInput => Some(Self::CallInput(CallInputSelector::Receiver)),
            QueryStepOp::ReceiverTargets => {
                Some(Self::ReceiverTargets(ReceiverTraversalFilter::default()))
            }
            QueryStepOp::PointsTo => Some(Self::PointsTo(ReceiverTraversalFilter::default())),
            QueryStepOp::MemberTargets => {
                Some(Self::MemberTargets(ReceiverTraversalFilter::default()))
            }
        }
    }

    pub fn output_kind(&self, input: QueryValueKind) -> Option<QueryValueKind> {
        match (self, input) {
            (Self::EnclosingDecl, QueryValueKind::StructuralMatch) => {
                Some(QueryValueKind::Declaration)
            }
            (
                Self::FileOf,
                QueryValueKind::StructuralMatch
                | QueryValueKind::Declaration
                | QueryValueKind::ReferenceSite
                | QueryValueKind::CallSite
                | QueryValueKind::ExpressionSite
                | QueryValueKind::ReceiverAnalysis,
            ) => Some(QueryValueKind::File),
            (Self::ImportsOf | Self::ImportersOf, QueryValueKind::File) => {
                Some(QueryValueKind::File)
            }
            (
                Self::Supertypes(_) | Self::Subtypes(_) | Self::Members | Self::Owner,
                QueryValueKind::Declaration,
            ) => Some(QueryValueKind::Declaration),
            (Self::ReferencesOf(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::ReferenceSite)
            }
            (Self::UsedBy(_) | Self::Uses(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::Callers(_) | Self::Callees(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::CallSitesTo(_) | Self::CallSitesFrom(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::CallSite)
            }
            (Self::CallInput(_), QueryValueKind::CallSite) => Some(QueryValueKind::ExpressionSite),
            (
                Self::ReceiverTargets(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::CallSite
                | QueryValueKind::ExpressionSite,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (
                Self::PointsTo(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::ExpressionSite,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (
                Self::MemberTargets(_),
                QueryValueKind::StructuralMatch | QueryValueKind::ReferenceSite,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            _ => None,
        }
    }
}

pub(super) fn validate_query_steps(
    steps: &[QueryStep],
    input: QueryValueKind,
    path: &str,
) -> Result<QueryValueKind, QueryError> {
    if steps.len() > MAX_QUERY_STEPS {
        return Err(QueryError::new(
            path,
            format!("at most {MAX_QUERY_STEPS} query steps are allowed"),
        ));
    }

    let mut value_kind = input;
    for (index, step) in steps.iter().enumerate() {
        let expected_input = match step {
            QueryStep::EnclosingDecl => "structural_match",
            QueryStep::FileOf => {
                "structural_match, declaration, reference_site, call_site, expression_site, or receiver_analysis"
            }
            QueryStep::ImportsOf | QueryStep::ImportersOf => "file",
            QueryStep::Supertypes(_)
            | QueryStep::Subtypes(_)
            | QueryStep::Members
            | QueryStep::Owner => "declaration",
            QueryStep::ReferencesOf(_) | QueryStep::UsedBy(_) | QueryStep::Uses(_) => "declaration",
            QueryStep::Callers(_)
            | QueryStep::Callees(_)
            | QueryStep::CallSitesTo(_)
            | QueryStep::CallSitesFrom(_) => "declaration",
            QueryStep::CallInput(_) => "call_site",
            QueryStep::ReceiverTargets(_) => {
                "structural_match, reference_site, call_site, or expression_site"
            }
            QueryStep::PointsTo(_) => "structural_match, reference_site, or expression_site",
            QueryStep::MemberTargets(_) => "structural_match or reference_site",
        };
        value_kind = step.output_kind(value_kind).ok_or_else(|| {
            QueryError::new(
                format!("{path}[{index}]"),
                format!(
                    "step {} requires {expected_input}, but the previous stage produces {}",
                    step.label(),
                    value_kind.label()
                ),
            )
        })?;
    }
    Ok(value_kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOperator {
    Union,
    Intersect,
    Except,
}

impl SetOperator {
    pub const ALL: [Self; 3] = [Self::Union, Self::Intersect, Self::Except];

    pub fn label(self) -> &'static str {
        match self {
            Self::Union => "union",
            Self::Intersect => "intersect",
            Self::Except => "except",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "union" => Some(Self::Union),
            "intersect" => Some(Self::Intersect),
            "except" => Some(Self::Except),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeQueryResultDetail {
    Compact,
    Full,
}

impl CodeQueryResultDetail {
    pub const ALL: [Self; 2] = [Self::Compact, Self::Full];

    pub fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Full => "full",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "compact" => Some(Self::Compact),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn is_compact(self) -> bool {
        matches!(self, Self::Compact)
    }
}

/// One structural seed before typed semantic pipeline transformations.
#[derive(Debug, Clone)]
pub struct CodeQuerySeed {
    /// Path globs relative to the workspace root; empty means all files.
    pub where_globs: Vec<glob::Pattern>,
    /// Language filter; empty means all languages with structural adapters.
    pub languages: Vec<Language>,
    pub root: Pattern,
    /// The root match must be lexically contained in a node matching this.
    pub inside: Option<Pattern>,
    /// Verifier-only negative containment: never used for candidate pruning.
    pub not_inside: Option<Pattern>,
}

/// The source of values entering one typed pipeline suffix.
#[derive(Debug, Clone)]
pub enum CodeQueryPlanSource {
    Seed(Box<CodeQuerySeed>),
    Set {
        op: SetOperator,
        branches: Vec<CodeQueryPlan>,
    },
}

/// A structural seed or compatible set composition followed by typed steps.
#[derive(Debug, Clone)]
pub struct CodeQueryPlan {
    pub source: CodeQueryPlanSource,
    pub steps: Vec<QueryStep>,
}

/// A canonical typed code query. Both JSON and RQL parse into this model.
#[derive(Debug, Clone)]
pub struct CodeQuery {
    pub schema_version: u64,
    pub plan: CodeQueryPlan,
    pub limit: usize,
    pub result_detail: CodeQueryResultDetail,
    pub execution_mode: CodeQueryExecutionMode,
}

impl CodeQuery {
    pub fn seed(&self) -> Option<&CodeQuerySeed> {
        match &self.plan.source {
            CodeQueryPlanSource::Seed(seed) => Some(seed),
            CodeQueryPlanSource::Set { .. } => None,
        }
    }

    /// Validate the semantic pipeline independently of its JSON/RQL origin.
    /// Embedders may construct this public IR directly, so execution cannot
    /// rely solely on decoder validation.
    pub fn validate_steps(&self) -> Result<QueryValueKind, QueryError> {
        let mut nodes = 0;
        validate_plan(&self.plan, "", 0, &mut nodes).map(|domain| domain.kind)
    }
}

#[derive(Debug)]
struct ValidatedDomain {
    kind: QueryValueKind,
    captures: Option<std::collections::HashSet<String>>,
}

fn validate_plan(
    plan: &CodeQueryPlan,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<ValidatedDomain, QueryError> {
    if depth > MAX_QUERY_PLAN_DEPTH {
        return Err(QueryError::new(
            path,
            format!("query plan depth must be at most {MAX_QUERY_PLAN_DEPTH}"),
        ));
    }
    *nodes += 1;
    if *nodes > MAX_QUERY_PLAN_NODES {
        return Err(QueryError::new(
            path,
            format!("query plan may contain at most {MAX_QUERY_PLAN_NODES} nodes"),
        ));
    }

    let mut domain = match &plan.source {
        CodeQueryPlanSource::Seed(seed) => ValidatedDomain {
            kind: QueryValueKind::StructuralMatch,
            captures: Some(seed.positive_capture_names()),
        },
        CodeQueryPlanSource::Set { op, branches } => {
            let op_path = child_query_path(path, op.label());
            if branches.len() < 2 {
                return Err(QueryError::new(
                    &op_path,
                    format!("{} requires at least two branches", op.label()),
                ));
            }
            if branches.len() > MAX_QUERY_BRANCHES {
                return Err(QueryError::new(
                    &op_path,
                    format!("at most {MAX_QUERY_BRANCHES} branches are allowed"),
                ));
            }
            let mut branch_domains = Vec::with_capacity(branches.len());
            for (index, branch) in branches.iter().enumerate() {
                let branch_path = format!("{op_path}[{index}]");
                branch_domains.push(validate_plan(branch, &branch_path, depth + 1, nodes)?);
            }
            let expected = branch_domains[0].kind;
            for (index, branch) in branch_domains.iter().enumerate().skip(1) {
                if branch.kind != expected {
                    return Err(QueryError::new(
                        format!("{op_path}[{index}]"),
                        format!(
                            "{} branch produces {}, but the first branch produces {}",
                            op.label(),
                            branch.kind.label(),
                            expected.label()
                        ),
                    ));
                }
            }
            let captures = if expected == QueryValueKind::StructuralMatch {
                let mut common = branch_domains[0].captures.clone().unwrap_or_default();
                if *op != SetOperator::Except {
                    for branch in &branch_domains[1..] {
                        common.retain(|capture| {
                            branch
                                .captures
                                .as_ref()
                                .is_some_and(|captures| captures.contains(capture))
                        });
                    }
                }
                Some(common)
            } else {
                None
            };
            ValidatedDomain {
                kind: expected,
                captures,
            }
        }
    };

    let steps_path = child_query_path(path, "steps");
    let output = validate_query_steps(&plan.steps, domain.kind, &steps_path)?;
    let mut input = domain.kind;
    for (index, step) in plan.steps.iter().enumerate() {
        let filter = match step {
            QueryStep::ReceiverTargets(filter)
            | QueryStep::PointsTo(filter)
            | QueryStep::MemberTargets(filter) => filter,
            _ => {
                input = step
                    .output_kind(input)
                    .expect("typed steps were validated above");
                continue;
            }
        };
        if let Some(capture) = &filter.capture {
            let capture_path = format!("{steps_path}[{index}].capture");
            if input != QueryValueKind::StructuralMatch {
                return Err(QueryError::new(
                    capture_path,
                    "capture is allowed only when the preceding stage produces structural_match",
                ));
            }
            if capture.is_empty() {
                return Err(QueryError::new(
                    capture_path,
                    "capture name must not be empty",
                ));
            }
            if capture.len() > MAX_CAPTURE_LENGTH {
                return Err(QueryError::new(
                    capture_path,
                    format!("capture name must be at most {MAX_CAPTURE_LENGTH} bytes"),
                ));
            }
            if !domain
                .captures
                .as_ref()
                .is_some_and(|captures| captures.contains(capture))
            {
                return Err(QueryError::new(
                    capture_path,
                    format!(
                        "capture {capture:?} is not declared by a positive pattern in every contributing branch"
                    ),
                ));
            }
        }
        input = step
            .output_kind(input)
            .expect("typed steps were validated above");
    }
    domain.kind = output;
    if output != QueryValueKind::StructuralMatch {
        domain.captures = None;
    }
    Ok(domain)
}

fn child_query_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}

impl CodeQuerySeed {
    fn positive_capture_names(&self) -> std::collections::HashSet<String> {
        let mut captures = std::collections::HashSet::new();
        let mut stack = vec![&self.root];
        if let Some(inside) = &self.inside {
            stack.push(inside);
        }
        while let Some(pattern) = stack.pop() {
            if let Some(capture) = pattern.capture.as_deref() {
                captures.insert(capture.to_string());
            }
            if let Some(has) = pattern.has.as_deref() {
                stack.push(has);
            }
            for role in Role::single_target_roles() {
                if let Some(child) = pattern.single_role_pattern(*role) {
                    stack.push(child);
                }
            }
            for role in Role::list_target_roles() {
                stack.extend(pattern.list_role_patterns(*role));
            }
            stack.extend(pattern.kwargs.iter().map(|(_, pattern)| pattern));
        }
        captures
    }
}

/// Predicate over a string attribute of a fact (its name or source text).
#[derive(Debug, Clone)]
pub enum StringPredicate {
    Exact(String),
    Regex(Regex),
}

impl StringPredicate {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            StringPredicate::Exact(expected) => value == expected,
            StringPredicate::Regex(regex) => regex.is_match(value),
        }
    }
}

/// One node pattern. All fields optional; the *root* `match` pattern must
/// constrain at least one of kind/name/text (a wildcard root would match
/// every node in the workspace), while nested patterns may be capture-only
/// or empty (an empty `args` entry means "some argument exists").
#[derive(Debug, Clone, Default)]
pub struct Pattern {
    /// JSON `kind`: a union of kinds, each subtype-aware (`literal` matches
    /// `string_literal`; `["function", "method"]` matches either). Empty
    /// means unconstrained. There is deliberately no exact-match variant:
    /// leaf kinds are their own exact match, and "exactly an abstract kind"
    /// would only select facts from adapters too coarse to classify further —
    /// adapter precision is surfaced through diagnostics, not query
    /// semantics.
    pub kinds: Vec<NormalizedKind>,
    /// JSON `not_kind`: subtype-aware exclusion, verifier-only (never used
    /// for candidate pruning). `{"kind": "callable", "not_kind":
    /// ["constructor", "lambda"]}` matches named functions and methods.
    pub not_kinds: Vec<NormalizedKind>,
    pub name: Option<StringPredicate>,
    pub text: Option<StringPredicate>,
    pub capture: Option<String>,
    pub has: Option<Box<Pattern>>,
    /// Verifier-only: never used for candidate pruning.
    pub not_has: Option<Box<Pattern>>,
    // Role sub-patterns. Only valid when `kind` is declared and the role is
    // valid for at least one of its kinds (see `Role::valid_for`).
    pub callee: Option<Box<Pattern>>,
    pub receiver: Option<Box<Pattern>>,
    /// Each listed pattern must match some positional argument; matches must
    /// appear in argument order but need not be contiguous.
    pub args: Vec<Pattern>,
    /// Named/keyword arguments: each entry must match the value of the
    /// keyword argument with that name.
    pub kwargs: Vec<(String, Pattern)>,
    pub left: Option<Box<Pattern>>,
    pub right: Option<Box<Pattern>>,
    pub module: Option<Box<Pattern>>,
    /// Each listed pattern must match some decorator/annotation.
    pub decorators: Vec<Pattern>,
    pub object: Option<Box<Pattern>>,
    pub field: Option<Box<Pattern>>,
}

impl Pattern {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
            && self.not_kinds.is_empty()
            && self.name.is_none()
            && self.text.is_none()
            && self.capture.is_none()
            && self.has.is_none()
            && self.not_has.is_none()
            && !self.constrains_roles()
    }

    fn constrains_roles(&self) -> bool {
        Role::single_target_roles()
            .iter()
            .any(|&role| self.single_role_pattern(role).is_some())
            || Role::list_target_roles()
                .iter()
                .any(|&role| !self.list_role_patterns(role).is_empty())
            || !self.kwargs.is_empty()
    }

    pub(crate) fn single_role_pattern(&self, role: Role) -> Option<&Pattern> {
        match role {
            Role::Callee => self.callee.as_deref(),
            Role::Receiver => self.receiver.as_deref(),
            Role::Left => self.left.as_deref(),
            Role::Right => self.right.as_deref(),
            Role::Module => self.module.as_deref(),
            Role::Object => self.object.as_deref(),
            Role::Field => self.field.as_deref(),
            Role::Arg | Role::Kwarg | Role::Decorator => None,
        }
    }

    pub(crate) fn list_role_patterns(&self, role: Role) -> &[Pattern] {
        match role {
            Role::Arg => &self.args,
            Role::Decorator => &self.decorators,
            Role::Callee
            | Role::Receiver
            | Role::Kwarg
            | Role::Left
            | Role::Right
            | Role::Module
            | Role::Object
            | Role::Field => &[],
        }
    }

    pub(crate) fn has_role_constraints(&self) -> bool {
        self.constrains_roles()
    }
}

/// A query rejection, carrying the JSON path of the offending field so
/// callers (especially agents) can self-correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub path: String,
    pub message: String,
}

impl QueryError {
    pub(super) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "invalid query: {}", self.message)
        } else {
            write!(f, "invalid query at {}: {}", self.path, self.message)
        }
    }
}

impl std::error::Error for QueryError {}
