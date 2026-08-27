//! Executable schema metadata for RQLP schema version 1.
//!
//! This module is the single vocabulary registry for policy and endpoint
//! authoring.  The source decoder, hover/completion support, formatter, and
//! conservative editor grammar consume (or are exhaustively checked against)
//! these descriptors instead of maintaining private keyword tables.

use super::definition::CvssMetricValueToken;
use brokk_bifrost_analysis::schema_version::{
    SchemaVersionDescriptor, SchemaVersionRegistry, SchemaVersionResolution,
    UnsupportedSchemaVersion,
};
use std::sync::OnceLock;

pub const POLICY_SCHEMA_VERSION: u32 = 1;

const POLICY_SCHEMA_VERSIONS: &[SchemaVersionDescriptor] = &[SchemaVersionDescriptor::new(
    POLICY_SCHEMA_VERSION,
    None,
    true,
)];

static POLICY_SCHEMA_VERSION_REGISTRY: OnceLock<SchemaVersionRegistry> = OnceLock::new();

pub(crate) fn resolve_policy_schema_version(
    authored_version: Option<u32>,
) -> Result<SchemaVersionResolution, UnsupportedSchemaVersion> {
    POLICY_SCHEMA_VERSION_REGISTRY
        .get_or_init(|| {
            SchemaVersionRegistry::new(POLICY_SCHEMA_VERSIONS)
                .expect("the compiled-in RQLP schema lineage must be valid")
        })
        .resolve(authored_version)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RqlpDocumentKind {
    Policy,
    Endpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAnalysisKind {
    Match,
    Taint,
    Typestate,
    Assertion,
    /// Policy-authored generic bounded value flow (#2436). Neutral
    /// provenance/correctness vocabulary over the same typed binding system
    /// taint uses; it is not a security classification.
    Flow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentOwners(u8);

impl DocumentOwners {
    const POLICY_BIT: u8 = 1;
    const ENDPOINT_BIT: u8 = 2;

    pub const POLICY: Self = Self(Self::POLICY_BIT);
    pub const ENDPOINT: Self = Self(Self::ENDPOINT_BIT);
    pub const BOTH: Self = Self(Self::POLICY_BIT | Self::ENDPOINT_BIT);

    pub const fn contains(self, kind: RqlpDocumentKind) -> bool {
        let bit = match kind {
            RqlpDocumentKind::Policy => Self::POLICY_BIT,
            RqlpDocumentKind::Endpoint => Self::ENDPOINT_BIT,
        };
        self.0 & bit != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisOwners(u8);

impl AnalysisOwners {
    const MATCH_BIT: u8 = 1;
    const TAINT_BIT: u8 = 2;
    const TYPESTATE_BIT: u8 = 4;
    const ASSERTION_BIT: u8 = 8;
    const FLOW_BIT: u8 = 16;

    pub const NONE: Self = Self(0);
    pub const MATCH: Self = Self(Self::MATCH_BIT);
    pub const TAINT: Self = Self(Self::TAINT_BIT);
    pub const TYPESTATE: Self = Self(Self::TYPESTATE_BIT);
    pub const ASSERTION: Self = Self(Self::ASSERTION_BIT);
    pub const FLOW: Self = Self(Self::FLOW_BIT);
    pub const TAINT_OR_TYPESTATE: Self = Self(Self::TAINT_BIT | Self::TYPESTATE_BIT);
    pub const TAINT_OR_FLOW: Self = Self(Self::TAINT_BIT | Self::FLOW_BIT);
    pub const TAINT_TYPESTATE_OR_FLOW: Self =
        Self(Self::TAINT_BIT | Self::TYPESTATE_BIT | Self::FLOW_BIT);
    /// Every analysis kind. Membership is audited record by record: the
    /// vocabulary carrying this applicability is policy metadata, report
    /// retention, taxonomy classification, and CVSS evidence, none of which
    /// reads the analysis kind, so the assertion kind belongs in all of it.
    pub const ALL: Self = Self(
        Self::MATCH_BIT
            | Self::TAINT_BIT
            | Self::TYPESTATE_BIT
            | Self::ASSERTION_BIT
            | Self::FLOW_BIT,
    );

    pub const fn contains(self, kind: PolicyAnalysisKind) -> bool {
        let bit = match kind {
            PolicyAnalysisKind::Match => Self::MATCH_BIT,
            PolicyAnalysisKind::Taint => Self::TAINT_BIT,
            PolicyAnalysisKind::Typestate => Self::TYPESTATE_BIT,
            PolicyAnalysisKind::Assertion => Self::ASSERTION_BIT,
            PolicyAnalysisKind::Flow => Self::FLOW_BIT,
        };
        self.0 & bit != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerApplicability {
    pub documents: DocumentOwners,
    pub analyses: AnalysisOwners,
}

impl OwnerApplicability {
    pub const POLICY_ALL: Self = Self::new(DocumentOwners::POLICY, AnalysisOwners::ALL);
    pub const POLICY_MATCH: Self = Self::new(DocumentOwners::POLICY, AnalysisOwners::MATCH);
    pub const POLICY_TAINT: Self = Self::new(DocumentOwners::POLICY, AnalysisOwners::TAINT);
    pub const POLICY_TYPESTATE: Self = Self::new(DocumentOwners::POLICY, AnalysisOwners::TYPESTATE);
    pub const POLICY_ASSERTION: Self = Self::new(DocumentOwners::POLICY, AnalysisOwners::ASSERTION);
    pub const POLICY_TAINT_OR_TYPESTATE: Self =
        Self::new(DocumentOwners::POLICY, AnalysisOwners::TAINT_OR_TYPESTATE);
    pub const POLICY_FLOW: Self = Self::new(DocumentOwners::POLICY, AnalysisOwners::FLOW);
    pub const POLICY_TAINT_OR_FLOW: Self =
        Self::new(DocumentOwners::POLICY, AnalysisOwners::TAINT_OR_FLOW);
    /// Reusable endpoint documents have no analysis discriminator, while
    /// policy documents may use the row selector only for taint or flow.
    pub const ENDPOINT_OR_POLICY_TAINT_OR_FLOW: Self =
        Self::new(DocumentOwners::BOTH, AnalysisOwners::TAINT_OR_FLOW);
    pub const POLICY_TAINT_TYPESTATE_OR_FLOW: Self = Self::new(
        DocumentOwners::POLICY,
        AnalysisOwners::TAINT_TYPESTATE_OR_FLOW,
    );
    pub const ENDPOINT: Self = Self::new(DocumentOwners::ENDPOINT, AnalysisOwners::NONE);
    pub const BOTH: Self = Self::new(DocumentOwners::BOTH, AnalysisOwners::ALL);

    pub const fn new(documents: DocumentOwners, analyses: AnalysisOwners) -> Self {
        Self {
            documents,
            analyses,
        }
    }

    /// Whether this vocabulary is legal for a document/analysis context.
    ///
    /// Endpoint documents do not have an analysis discriminator, so their
    /// document bit is sufficient. Policy vocabulary always requires the
    /// concrete analysis kind selected by `(analysis :type ...)`.
    pub const fn allows(
        self,
        document: RqlpDocumentKind,
        analysis: Option<PolicyAnalysisKind>,
    ) -> bool {
        if !self.documents.contains(document) {
            return false;
        }
        match document {
            RqlpDocumentKind::Endpoint => true,
            RqlpDocumentKind::Policy => match analysis {
                Some(kind) => self.analyses.contains(kind),
                None => false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordLayout {
    /// The head symbol is followed only by `:keyword value` pairs.
    KeywordPairs,
    /// Keyword pairs may precede one or more positional values.
    Mixed,
    /// The head symbol is followed only by positional values.
    Positional,
}

macro_rules! policy_records {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        layout: $layout:ident,
        owner: $owner:expr,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum PolicyRecord {
            $($variant,)+
        }

        pub const ALL_POLICY_RECORDS: &[PolicyRecord] = &[
            $(PolicyRecord::$variant,)+
        ];

        impl PolicyRecord {
            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn layout(self) -> RecordLayout {
                match self {
                    $(Self::$variant => RecordLayout::$layout,)+
                }
            }

            pub fn applicability(self) -> OwnerApplicability {
                match self {
                    $(Self::$variant => $owner,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

policy_records! {
    Policy { labels: ["policy"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(policy [:schema-version N] :id ID :name NAME :message MESSAGE :severity SEVERITY :analysis ANALYSIS ...)", description: "Define one executable static-analysis policy." }
    Endpoint { labels: ["endpoint"], layout: KeywordPairs, owner: OwnerApplicability::ENDPOINT, signature: "(endpoint [:schema-version N] :id ID :name NAME :display-name TEXT :role source|sink ...)", description: "Define one diagnostic-neutral reusable source or sink endpoint." }
    Analysis { labels: ["analysis"], layout: Mixed, owner: OwnerApplicability::POLICY_ALL, signature: "(analysis :type match|taint|typestate|assertion|flow ...)", description: "Select and configure exactly one policy analysis kind." }
    RowSelector { labels: ["row-selector"], layout: Mixed, owner: OwnerApplicability::ENDPOINT_OR_POLICY_TAINT_OR_FLOW, signature: "(row-selector :output NAME (bind|filter|project|join|call|call-argument) ...)", description: "Select one bounded typed relational endpoint relation from exact call and binding rows." }
    Bind { labels: ["bind"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(bind :name NAME (:query SELECTOR | :from NAME :step STEP))", description: "Bind one named typed row relation from a CodeQuery or an earlier binding expansion." }
    Filter { labels: ["filter"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(filter :over NAME :where ((BINDING.FIELD OP VALUE)...))", description: "Narrow one named row relation to the rows that satisfy every listed typed predicate. The relation keeps its name and its columns; only its rows change." }
    Project { labels: ["project"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(project :name NEW :from NAME :columns (BINDING.FIELD|(BINDING.FIELD NEW-FIELD)...))", description: "Publish a new named row relation holding chosen, optionally renamed, columns of an existing one. The projected relation takes the place of the one it reads." }
    Join { labels: ["join"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(join :left NAME :right NAME [:kind inner|semi|anti] :on ((LEFT RIGHT)...))", description: "Join two named row relations by registered equal-typed fields." }
    Group { labels: ["group"], layout: Mixed, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(group :name NAME :by (BINDING.FIELD...) (aggregate ...) ...)", description: "Group joined rows by registered fields and compute named aggregates." }
    Aggregate { labels: ["aggregate"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(aggregate :name NAME :op min|max|count|count-distinct|any|all|ordered-equal [:value BINDING.FIELD] [:left (BINDING.POSITION BINDING.VALUE) :right (BINDING.POSITION BINDING.VALUE)] [:where ((BINDING.FIELD OP VALUE)...)] )", description: "Compute one bounded typed aggregate within a row group." }
    CallArgument { labels: ["call-argument"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(call-argument :over NAME :formal-name \"NAME\") | (call-argument :over NAME :formal-index N)", description: "Select actual call arguments bound exactly to one formal name or index. The in-place lowering also requires exhaustive coverage, a non-terminal row, and a source argument identity." }
    Call { labels: ["call"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(call :over NAME :resolves-to MODEL_ID :proof exact)", description: "Select call-binding rows for one exact semantic-model symbol identity. The in-place lowering requires a singular resolved dispatch with exhaustive, proven, complete evidence and a selected signature." }
    RowAssert { labels: ["assert"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert [:id ID] :group NAME :value NAME :cardinality (exactly|at-least|at-most N))", description: "Assert a cardinality over one named aggregate in every row group." }
    RowAssertSelectedInWinningTier { labels: ["assert-selected-in-winning-tier"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-selected-in-winning-tier :id ID :site NAME :candidates NAME [:cardinality (exactly|at-least|at-most N)])", description: "Require the selected candidate of every overload-selection row to sit in the winning applicability tier, meaning the set of candidates the resolver's own applicability check accepted. Authoring sugar: it lowers to one inner join on site_ast_id, one group keyed on the site, one counting aggregate over selected applicable candidates, and one cardinality assertion, and adds no evaluation rule of its own." }
    Assert { labels: ["assert"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert :id ID :at CAPTURE :role ROLE :expect declaration|reference|binding|none [:cardinality (exactly N)] [:namespace NAMESPACE] [:require-target true|false])", description: "Require or forbid occurrences at one captured AST node with exact cardinality." }
    AssertResolution { labels: ["assert-resolution"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-resolution :id ID :at CAPTURE :role ROLE :expect-tier TIER [:at-least true|false] [:forbid-tier TIER] [:require-unique true|false])", description: "Require the resolver's selected candidate for one captured reference to sit at, or above, one precedence tier." }
    AssertBindingScope { labels: ["assert-binding-scope"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-binding-scope :id ID :at CAPTURE :role ROLE :declared inside|outside :relative-to CAPTURE)", description: "Require the binding of one captured reference to be declared inside or outside a second captured node." }
    AssertValueOrigin { labels: ["assert-value-origin"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-value-origin :id ID :at CAPTURE :role ROLE :established inside|outside :relative-to CAPTURE)", description: "Require the value read at one captured reference to be established -- by its binding's declaring scope, or by an assignment reaching that binding -- inside or outside a second captured node." }
    AssertOriginShape { labels: ["assert-origin-shape"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-origin-shape :id ID :at LOOP_CAPTURE :anchor CAPTURE :role ROLE :shape collection-literal :max-elements N)", description: "Require the captured loop's iterated expression to provably originate from a collection literal with at most N elements. Inverted polarity: anything short of positive proof -- a loop with no iterated expression in evidence, no lexical binding, no establishing initializer, or a non-qualifying initializer -- violates and keeps the finding, which anchors at the anchor capture." }
    AssertBoundary { labels: ["assert-boundary"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-boundary :id ID :at CAPTURE :role ROLE :forbid-fallback-past external_declared_unindexed|external_unknown)", description: "Forbid a name-only fallback selection once resolution reached or passed one authoritative boundary." }
    AssertGeneration { labels: ["assert-generation"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-generation :id ID :at CAPTURE [:kind KIND] [:cardinality (exactly N)] [:forbid-dynamic true|false])", description: "Require one captured generation site to materialize an exact generated set, optionally forbidding dynamic inputs." }
    AssertDeclarationState { labels: ["assert-declaration-state"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-declaration-state :id ID :at CAPTURE [:origin ORIGIN] [:declaration-only true|false] [:config-gated true|false])", description: "Require one captured declaration's state row to carry an expected origin, declaration-only flag, or configuration gate." }
    AssertEdgeParity { labels: ["assert-edge-parity"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-edge-parity :id ID :at CAPTURE :role ROLE [:surface external-usages|lsp-references])", description: "Require field-for-field agreement between the forward and inverse reference-edge projections at the captured token, within one workspace generation." }
    AssertEdgeClass { labels: ["assert-edge-class"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-edge-class :id ID :at CAPTURE :role ROLE :axis relation|usage|site-class|kind [:require [..]] [:forbid [..]] [:surface external-usages|lsp-references])", description: "Require or forbid typed classifications on the captured token's reference edges." }
    AssertCanonical { labels: ["assert-canonical"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-canonical :id ID :at CAPTURE :role ROLE :equals CAPTURE :equals-role ROLE [:distinct true|false])", description: "Require two captured tokens' resolved declarations to share, or not share, one canonical identity." }
    AssertRoute { labels: ["assert-route"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-route :id ID :at CAPTURE :role ROLE :to CAPTURE :to-role ROLE [:via HOP] [:forbid HOP])", description: "Require an identity route from the captured site to a second capture's declaration, optionally via or never via one hop kind." }
    AssertRoundTrip { labels: ["assert-round-trip"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-round-trip :id ID :at CAPTURE :role ROLE)", description: "Require forward resolution and inverse enumeration to round-trip the captured site." }
    AssertFlowEstablishment { labels: ["assert-flow-establishment"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-flow-establishment :id ID :at CAPTURE :role ROLE [:require dominated|reached] [:forbid-same-evaluation true|false])", description: "Require control flow to have established the captured subject before the read: some path carries an establishment to it (:require reached, the default), or every entry-to-read path passes one (:require dominated). Optionally forbid an establishment from serving a read of its own evaluation." }
    AssertRewriteTermination { labels: ["assert-rewrite-termination"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(assert-rewrite-termination :id ID :domain DOMAIN [:scope CAPTURE])", description: "Require every bounded rewrite chase of one declared finite domain to converge within the bound the domain declares for itself. A repeated semantic state is a finding with its ordered witness; an exhausted budget is absence of evidence and makes the run inconclusive." }
    CardinalityExactly { labels: ["exactly"], layout: Positional, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(exactly N)", description: "Require exactly N joined occurrence rows." }
    CardinalityAtLeast { labels: ["at-least"], layout: Positional, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(at-least N)", description: "Require at least N joined occurrence rows." }
    CardinalityAtMost { labels: ["at-most"], layout: Positional, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(at-most N)", description: "Require at most N joined occurrence rows." }
    Rql { labels: ["rql"], layout: Mixed, owner: OwnerApplicability::BOTH, signature: "(rql [:schema-version N] QUERY)", description: "Embed one native RQL selector without rendering or reparsing it." }
    RqlFile { labels: ["rql-file"], layout: KeywordPairs, owner: OwnerApplicability::BOTH, signature: "(rql-file [:schema-version N] :path \"workspace/relative.rql\")", description: "Reference one workspace-relative RQL selector for deferred loading." }
    GeneratedMessage { labels: ["generated-message"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(generated-message :relation can-reach)", description: "Generate the fixed source-display can-reach sink-display message after proven flow." }
    CvssSeverity { labels: ["cvss-severity"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(cvss-severity :when-unscored unrated|note|warning|error)", description: "Derive severity from CVSS with an explicit unscored fallback." }
    Argument { labels: ["argument"], layout: KeywordPairs, owner: OwnerApplicability::BOTH, signature: "(argument :index N) | (argument :name \"NAME\")", description: "Bind a zero-based argument index or exact formal argument name." }
    SourceSemantics { labels: ["source-semantics"], layout: KeywordPairs, owner: OwnerApplicability::ENDPOINT, signature: "(source-semantics :labels [LABEL...] [:evidence EVIDENCE])", description: "Attach diagnostic-neutral taint source semantics to a source endpoint." }
    SinkSemantics { labels: ["sink-semantics"], layout: KeywordPairs, owner: OwnerApplicability::ENDPOINT, signature: "(sink-semantics :accepts [LABEL...] [:tags [...]] [:impacts [...]])", description: "Attach diagnostic-neutral taint sink semantics to a sink endpoint." }
    Evidence { labels: ["evidence"], layout: KeywordPairs, owner: OwnerApplicability::BOTH, signature: "(evidence [:trust-boundary VALUE] [:system-entry VALUE])", description: "Record coherent source evidence; at least one field is required." }
    Report { labels: ["report"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(report [:witness WITNESS] [:witnesses-per-finding N] [:origins-per-finding N])", description: "Bound witness and origin retention for each finding." }
    Witness { labels: ["witness"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(witness [:max-steps N] [:max-bytes N])", description: "Bound the retained steps and encoded bytes of one witness." }
    EndpointSet { labels: ["endpoint-set"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT_OR_FLOW, signature: "(endpoint-set [:include-sets [...]] [:include-matches [...]] [:entries [...]])", description: "Compose a typed endpoint set from catalogs, endpoint matches, and local entries. A flow analysis composes only local entries." }
    Catalog { labels: ["catalog"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(catalog :name ID :version N [:sha256 HEX])", description: "Reference an explicitly registered, optionally content-pinned taint catalog." }
    MatchDirectory { labels: ["match-directory"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(match-directory :path PATH :scope direct|recursive [:role source|sink] [:phase PHASE] :categories (any|all [...]) [:manifest-sha256 HEX])", description: "Select endpoint leaves transactionally from an explicit capability-rooted directory." }
    MatchEndpoints { labels: ["match-endpoints"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(match-endpoints :ids [ENDPOINT-ID...] [:role source|sink] [:phase PHASE])", description: "Select exact endpoint IDs already present in the immutable endpoint index." }
    CategoryAny { labels: ["any"], layout: Positional, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(any [CATEGORY...])", description: "Require at least one exact category from a non-empty set." }
    CategoryAll { labels: ["all"], layout: Positional, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(all [CATEGORY...])", description: "Require every exact category from a non-empty set." }
    CategoriesPredicate { labels: ["categories"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(categories :any [...] | :all [...])", description: "Select endpoints by an exact any-or-all category predicate." }
    EndpointsPredicate { labels: ["endpoints"], layout: Positional, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(endpoints [ENDPOINT-REF...])", description: "Select a finite exact set of local, catalog, or match endpoint identities." }
    EndpointRef { labels: ["endpoint-ref"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "(endpoint-ref (:local ID | :catalog CATALOG :entry ID | :match-endpoint ID))", description: "Name one endpoint in the current policy, an explicit catalog, or the endpoint index." }
    Source { labels: ["source"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(source :id ID :display-name TEXT :categories [...] :selector SELECTOR :bind PORT :labels [...] [:evidence EVIDENCE])", description: "Declare one policy-local taint source." }
    Sink { labels: ["sink"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(sink :id ID :display-name TEXT :categories [...] :selector SELECTOR :dangerous-operand PORT :accepts [...] [:tags [...]] [:impacts [...]])", description: "Declare one policy-local taint sink." }
    Sanitizer { labels: ["sanitizer"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(sanitizer :id ID :selector SELECTOR :input PORT :output PORT :removes [LABEL...])", description: "Declare one policy-local sanitizer transfer." }
    Origin { labels: ["origin"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_FLOW, signature: "(origin :id ID :display-name TEXT :selector SELECTOR :bind PORT)", description: "Declare one value-flow origin: the site and typed port where the tracked value is established." }
    Observation { labels: ["observation"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_FLOW, signature: "(observation :id ID :display-name TEXT :selector SELECTOR :observed-operand PORT)", description: "Declare one value-flow observation: the site and typed port that consumes the tracked value." }
    Kill { labels: ["kill"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_FLOW, signature: "(kill :id ID :selector SELECTOR :input PORT :output PORT)", description: "Declare one value-flow kill: at this site the output port no longer carries the tracked value established at the input port." }
    TransformEntry { labels: ["transform"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(transform :id ID :selector SELECTOR :input PORT :output PORT [:removes [...]] [:adds [...]])", description: "Declare one policy-local label transform." }
    ExternalModel { labels: ["external-model"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(external-model :id ID :selector SELECTOR :transfers [TRANSFER...])", description: "Declare typed transfer behavior for one external API." }
    Transfer { labels: ["transfer"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(transfer :from PORT :to PORT :labels [LABEL...] :effect EFFECT)", description: "Move selected labels between two typed external-model ports." }
    SanitizeEffect { labels: ["sanitize"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(sanitize :removes [LABEL...])", description: "Remove one or more labels during an external transfer." }
    TransformEffect { labels: ["transform"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(transform [:removes [...]] [:adds [...]])", description: "Remove and/or add labels during an external transfer." }
    FindingCombination { labels: ["finding-combination"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(finding-combination :id ID :source PREDICATE :sink PREDICATE :message TEXT ...)", description: "Override generic presentation for one finite source/sink endpoint combination." }
    SubjectSet { labels: ["subject-set"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(subject-set [:include-matches [...]] [:entries [...]])", description: "Compose the values newly tracked by a typestate policy." }
    Subject { labels: ["subject"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(subject :id ID :selector SELECTOR :subject BINDING)", description: "Declare one policy-local typestate seed and its bound subject." }
    CallModeling { labels: ["call-modeling"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT_TYPESTATE_OR_FLOW, signature: "(call-modeling :unmodeled paranoid|optimistic|require-model)", description: "Choose fallback semantics for call arms without an executable body or applicable model." }
    Uncertainty { labels: ["uncertainty"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(uncertainty :escape inconclusive)", description: "Make escape capability gaps explicit." }
    Automaton { labels: ["automaton"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(automaton :states [...] :initial STATE :accepting-states [...] :error-states [...] :events [...] :transitions [...] [:terminal-expectations [...]])", description: "Define the public typestate states, events, transitions, and terminal obligations." }
    Event { labels: ["event"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(event :id ID (:calls CALLS | :matches MATCH-SET | :on SEMANTIC-EVENT) ...)", description: "Define one direct-call, endpoint, or semantic typestate event." }
    Calls { labels: ["calls"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(calls :selector SELECTOR :subject BINDING :phase PHASE)", description: "Observe a direct call selector using one tracked receiver, return, or argument binding." }
    Transition { labels: ["transition"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(transition :from STATE :on EVENT :to STATE)", description: "Apply one deterministic typestate transition." }
    TerminalExpectation { labels: ["terminal-expectation"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(terminal-expectation :id ID (:matches MATCH-SET | :on SEMANTIC-EVENT) :expected-states [...])", description: "Require an accepting state after an explicit or implicit terminal observation." }
    NormalProcedureExit { labels: ["normal-procedure-exit"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(normal-procedure-exit :scope analysis-root)", description: "Observe normal completion of the outer analysis root." }
    ExceptionalProcedureExit { labels: ["exceptional-procedure-exit"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(exceptional-procedure-exit :scope analysis-root)", description: "Observe exceptional completion of the outer analysis root." }
    Classification { labels: ["classification"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(classification :fallback CLASSIFICATION [:refinements [...]] [:cvss CVSS])", description: "Declare a broad taxonomy classification, ordered refinements, and optional CVSS policy." }
    ClassificationId { labels: ["classification-id"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(classification-id :taxonomy \"NAME\" :id \"IDENTIFIER\" [:name \"DISPLAY NAME\"])", description: "Name one taxonomy classification without deriving semantics from its text." }
    Refinement { labels: ["refinement"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(refinement :when PREDICATE :add [CLASSIFICATION...])", description: "Add classifications when a typed evidence predicate holds." }
    PredicateAll { labels: ["all"], layout: Positional, owner: OwnerApplicability::POLICY_ALL, signature: "(all [PREDICATE...])", description: "Require every non-empty child evidence predicate." }
    PredicateAny { labels: ["any"], layout: Positional, owner: OwnerApplicability::POLICY_ALL, signature: "(any [PREDICATE...])", description: "Require at least one non-empty child evidence predicate." }
    CvssPredicateAll { labels: ["all"], layout: Positional, owner: OwnerApplicability::POLICY_ALL, signature: "(all [CVSS-EVIDENCE-PREDICATE...])", description: "Require every non-empty child CVSS evidence predicate." }
    CvssPredicateAny { labels: ["any"], layout: Positional, owner: OwnerApplicability::POLICY_ALL, signature: "(any [CVSS-EVIDENCE-PREDICATE...])", description: "Require at least one non-empty child CVSS evidence predicate." }
    AnalysisTypePredicate { labels: ["analysis-type"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(analysis-type :is match|taint|typestate)", description: "Match the current typed analysis kind." }
    SourceCategoriesPredicate { labels: ["source-categories"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(source-categories (:any [...] | :all [...]))", description: "Match exact categories on the resolved source endpoint." }
    SinkCategoriesPredicate { labels: ["sink-categories"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(sink-categories (:any [...] | :all [...]))", description: "Match exact categories on the resolved sink endpoint." }
    SourceLabelsPredicate { labels: ["source-labels"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(source-labels (:any [...] | :all [...]))", description: "Match normalized labels on the resolved source endpoint." }
    SinkTagsPredicate { labels: ["sink-tags"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(sink-tags (:any [...] | :all [...]))", description: "Match normalized tags on the resolved sink endpoint." }
    SinkImpactsPredicate { labels: ["sink-impacts"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(sink-impacts (:any [...] | :all [...]))", description: "Match normalized impacts on the resolved sink endpoint." }
    FindingCombinationPredicate { labels: ["finding-combination"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(finding-combination :id ID)", description: "Match the selected intentional finding-combination identity." }
    TypestateExpectationPredicate { labels: ["typestate-expectation"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TYPESTATE, signature: "(typestate-expectation :id ID)", description: "Match the violated typestate terminal-expectation identity." }
    Cvss { labels: ["cvss"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(cvss :version \"4.0\" :emit when-base-complete :metric-rules [METRIC...])", description: "Establish evidence-backed CVSS v4.0 Base metrics without authored scores." }
    Metric { labels: ["metric"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_ALL, signature: "(metric :name BASE-METRIC :value VALUE :when PREDICATE :basis policy-assertion :scope SCOPE :evidence-refs [...] :rationale TEXT [:assumptions [...]])", description: "Establish one static CVSS Base metric from typed policy evidence." }
    SourceEvidence { labels: ["source-evidence"], layout: KeywordPairs, owner: OwnerApplicability::POLICY_TAINT, signature: "(source-evidence [:trust-boundary VALUE] [:system-entry VALUE])", description: "Match coherent trust-boundary and system-entry facts from one source scenario." }
}

/// Return every context-sensitive record candidate for an accepted head
/// spelling. Some spellings intentionally have more than one candidate (for
/// example `all`, `finding-combination`, and `transform`), so callers must use
/// the parent field shape and applicability rather than global label order.
pub fn records_from_label(label: &str) -> impl Iterator<Item = PolicyRecord> + '_ {
    ALL_POLICY_RECORDS
        .iter()
        .copied()
        .filter(move |record| record.labels().contains(&label))
}

pub fn applicable_records_from_label(
    label: &str,
    document: RqlpDocumentKind,
    analysis: Option<PolicyAnalysisKind>,
) -> impl Iterator<Item = PolicyRecord> + '_ {
    records_from_label(label)
        .filter(move |record| record.applicability().allows(document, analysis))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPlacement {
    Keyword,
    Positional {
        index: u8,
    },
    /// A bounded source-ordered tail of positional child values. At most one
    /// descriptor of this kind may exist for a record.
    VariadicPositional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRequiredness {
    Required,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOccurrence {
    /// A keyword/position may appear at most once. A second occurrence is a
    /// duplicate-field error even when its value is equal.
    Single,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRecordContext {
    /// The record is a top-level field value, dependency set member, subject
    /// seed, or another non-trigger use.
    Ordinary,
    TaintSources,
    TaintSinks,
    TaintSanitizers,
    TaintTransforms,
    TaintExternalModels,
    /// Generic value-flow origin entries (#2436).
    FlowOrigins,
    /// Generic value-flow observation entries (#2436).
    FlowObservations,
    /// Generic value-flow kill entries (#2436).
    FlowKills,
    /// The match set is the trigger of a typestate event or terminal
    /// expectation. In this context source `:role` and `:phase` are lifted
    /// into the typed trigger while `MatchDirectoryRef` retains only its
    /// path/scope/categories/manifest fields.
    TypestateTrigger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldContextApplicability {
    Any,
    TaintSourcesOnly,
    TaintSinksOnly,
    TaintSanitizersOnly,
    TaintTransformsOnly,
    TaintExternalModelsOnly,
    TaintSourceOrSinkOnly,
    FlowOriginsOnly,
    FlowObservationsOnly,
    FlowKillsOnly,
    TypestateTriggerOnly,
}

impl FieldContextApplicability {
    pub const fn allows(self, context: PolicyRecordContext) -> bool {
        match self {
            Self::Any => true,
            Self::TaintSourcesOnly => matches!(context, PolicyRecordContext::TaintSources),
            Self::TaintSinksOnly => matches!(context, PolicyRecordContext::TaintSinks),
            Self::TaintSanitizersOnly => {
                matches!(context, PolicyRecordContext::TaintSanitizers)
            }
            Self::TaintTransformsOnly => matches!(context, PolicyRecordContext::TaintTransforms),
            Self::TaintExternalModelsOnly => {
                matches!(context, PolicyRecordContext::TaintExternalModels)
            }
            Self::TaintSourceOrSinkOnly => matches!(
                context,
                PolicyRecordContext::TaintSources | PolicyRecordContext::TaintSinks
            ),
            Self::FlowOriginsOnly => matches!(context, PolicyRecordContext::FlowOrigins),
            Self::FlowObservationsOnly => {
                matches!(context, PolicyRecordContext::FlowObservations)
            }
            Self::FlowKillsOnly => matches!(context, PolicyRecordContext::FlowKills),
            Self::TypestateTriggerOnly => {
                matches!(context, PolicyRecordContext::TypestateTrigger)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionOrder {
    /// Values are normalized as a duplicate-free, deterministic set.
    Set,
    /// Source order is meaningful and must be preserved.
    SourceOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueMultiplicity {
    Scalar,
    Vector {
        minimum: usize,
        maximum: usize,
        order: CollectionOrder,
    },
}

impl ValueMultiplicity {
    pub const fn set(minimum: usize, maximum: usize) -> Self {
        Self::Vector {
            minimum,
            maximum,
            order: CollectionOrder::Set,
        }
    }

    pub const fn sequence(minimum: usize, maximum: usize) -> Self {
        Self::Vector {
            minimum,
            maximum,
            order: CollectionOrder::SourceOrder,
        }
    }
}

macro_rules! value_shapes {
    ($($variant:ident => $description:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum PolicyValueShape {
            $($variant,)+
        }

        impl PolicyValueShape {
            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }

            /// Return the closed atom domain for scalar shapes whose unit
            /// spellings are registry-defined. Record/string/integer/vector
            /// shapes return `None` and are decoded by their typed shape.
            pub fn atom_domain(self) -> Option<AtomDomain> {
                match self {
                    Self::AnalysisType => Some(AtomDomain::AnalysisType),
                    Self::GeneratedRelation => Some(AtomDomain::GeneratedRelation),
                    Self::Severity | Self::FixedOrUnratedSeverity => Some(AtomDomain::Severity),
                    Self::EndpointRole => Some(AtomDomain::EndpointRole),
                    Self::EndpointBinding | Self::PolicyPort | Self::TypestateBinding => {
                        Some(AtomDomain::Port)
                    }
                    Self::TypestateCallBinding | Self::ExternalModelPort => {
                        Some(AtomDomain::CallPort)
                    }
                    Self::TaintMode => Some(AtomDomain::TaintMode),
                    Self::UnmodeledCallBehavior => Some(AtomDomain::UnmodeledCallBehavior),
                    Self::TrustBoundary => Some(AtomDomain::TrustBoundary),
                    Self::SystemEntry => Some(AtomDomain::SystemEntry),
                    Self::DirectoryScope => Some(AtomDomain::DirectoryScope),
                    Self::TransferEffect => Some(AtomDomain::TransferEffect),
                    Self::InconclusivePolicy => Some(AtomDomain::Uncertainty),
                    Self::ObservationPhase => Some(AtomDomain::ObservationPhase),
                    Self::ExitScope => Some(AtomDomain::ExitScope),
                    Self::CvssVersion => Some(AtomDomain::CvssVersion),
                    Self::CvssEmitPolicy => Some(AtomDomain::CvssEmit),
                    Self::CvssBasis => Some(AtomDomain::CvssBasis),
                    Self::CvssScope => Some(AtomDomain::CvssScope),
                    Self::EvidenceReferences => Some(AtomDomain::EvidenceRef),
                    Self::OccurrenceRole => Some(AtomDomain::OccurrenceRole),
                    Self::ExpectedOccurrence => Some(AtomDomain::ExpectedOccurrence),
                    Self::OccurrenceNamespace => Some(AtomDomain::OccurrenceNamespace),
                    Self::Boolean => Some(AtomDomain::Boolean),
                    Self::PrecedenceTier => Some(AtomDomain::PrecedenceTier),
                    Self::GenerationKind => Some(AtomDomain::GenerationKind),
                    Self::DeclarationOrigin => Some(AtomDomain::DeclarationOrigin),
                    Self::DeclaredContainment => Some(AtomDomain::DeclaredContainment),
                    Self::OriginShape => Some(AtomDomain::OriginShape),
                    Self::BoundaryStrength => Some(AtomDomain::BoundaryStrength),
                    Self::UsageSurface => Some(AtomDomain::UsageSurface),
                    Self::EdgeClassAxis => Some(AtomDomain::EdgeClassAxis),
                    Self::EstablishmentRequirement => Some(AtomDomain::EstablishmentRequirement),
                    Self::RewriteDomain => Some(AtomDomain::RewriteDomain),
                    Self::RouteHop => Some(AtomDomain::RouteHop),
                    Self::RowExpansionStep => Some(AtomDomain::RowExpansionStep),
                    Self::RowJoinKind => Some(AtomDomain::RowJoinKind),
                    Self::RowAggregateOp => Some(AtomDomain::RowAggregateOp),
                    Self::CaptureName
                    | Self::AssertCardinality
                    | Self::AssertEntries
                    | Self::EdgeClassValues
                    | Self::AssertionPlanEntries
                    | Self::RowSelectorEntries => None,
                    Self::SchemaVersion
                    | Self::PolicyId
                    | Self::EndpointId
                    | Self::LocalEntryId
                    | Self::StateId
                    | Self::EventId
                    | Self::ExpectationId
                    | Self::CombinationId
                    | Self::Name
                    | Self::DisplayText
                    | Self::Message
                    | Self::Description
                    | Self::HelpUri
                    | Self::TaxonomyName
                    | Self::TaxonomyIdentifier
                    | Self::WorkspacePath
                    | Self::Sha256
                    | Self::NonNegativeInteger
                    | Self::PositiveInteger
                    | Self::AnalysisRecord
                    | Self::ReportOptions
                    | Self::WitnessOptions
                    | Self::Selector
                    | Self::RqlQuery
                    | Self::EndpointSemantics
                    | Self::TaintEndpointSet
                    | Self::MatchEndpointSet
                    | Self::CategoryPredicate
                    | Self::EndpointPredicate
                    | Self::CatalogRef
                    | Self::SourceEvidence
                    | Self::SemanticEvent
                    | Self::ClassificationSpec
                    | Self::TaxonomyClassification
                    | Self::ClassificationPredicate
                    | Self::CvssEvidencePredicate
                    | Self::CvssPolicy
                    | Self::CvssBaseMetric
                    | Self::CvssBaseMetricValue
                    | Self::PolicyTags
                    | Self::Categories
                    | Self::EndpointIds
                    | Self::StateIds
                    | Self::EventIds
                    | Self::ExpectationIds
                    | Self::CombinationIds
                    | Self::TaintLabels
                    | Self::TaintTags
                    | Self::TaintImpacts
                    | Self::Strings
                    | Self::CatalogRefs
                    | Self::MatchEndpointSets
                    | Self::EndpointRefs
                    | Self::SourceEntries
                    | Self::SinkEntries
                    | Self::SanitizerEntries
                    | Self::OriginEntries
                    | Self::ObservationEntries
                    | Self::KillEntries
                    | Self::TransformEntries
                    | Self::ExternalModelEntries
                    | Self::Transfers
                    | Self::FindingCombinations
                    | Self::SubjectSet
                    | Self::CallModelingSpec
                    | Self::UncertaintySpec
                    | Self::AutomatonSpec
                    | Self::CallsTrigger
                    | Self::TypestateSubjects
                    | Self::TypestateEvents
                    | Self::TypestateTransitions
                    | Self::TerminalExpectations
                    | Self::Classifications
                    | Self::ClassificationRefinements
                    | Self::Predicates
                    | Self::CvssPredicates
                    | Self::CvssMetrics
                    | Self::RowAggregates
                    | Self::RowName
                    | Self::RowFieldRef
                    | Self::RowFieldRefs
                    | Self::RowJoinConditions
                    | Self::RowOrderedSequence
                    | Self::RowProjectionColumns
                    | Self::RowPredicates => None,
                }
            }

            /// Record heads accepted by this value shape. An empty slice
            /// means the value is scalar/vector syntax or a native RQL tree.
            /// Union shapes may also accept atoms or strings as described by
            /// `atom_domain` and `description`.
            pub fn accepted_records(self) -> &'static [PolicyRecord] {
                match self {
                    Self::AnalysisRecord => &[PolicyRecord::Analysis],
                    Self::ReportOptions => &[PolicyRecord::Report],
                    Self::WitnessOptions => &[PolicyRecord::Witness],
                    Self::Message => &[PolicyRecord::GeneratedMessage],
                    Self::Severity => &[PolicyRecord::CvssSeverity],
                    Self::FixedOrUnratedSeverity => &[],
                    Self::Selector => &[
                        PolicyRecord::Rql,
                        PolicyRecord::RqlFile,
                        PolicyRecord::RowSelector,
                    ],
                    Self::EndpointBinding
                    | Self::PolicyPort
                    | Self::TypestateBinding
                    | Self::TypestateCallBinding
                    | Self::ExternalModelPort => &[PolicyRecord::Argument],
                    Self::EndpointSemantics => &[
                        PolicyRecord::SourceSemantics,
                        PolicyRecord::SinkSemantics,
                    ],
                    Self::TaintEndpointSet => &[PolicyRecord::EndpointSet],
                    Self::MatchEndpointSet | Self::MatchEndpointSets => &[
                        PolicyRecord::MatchDirectory,
                        PolicyRecord::MatchEndpoints,
                    ],
                    Self::CategoryPredicate => &[
                        PolicyRecord::CategoryAny,
                        PolicyRecord::CategoryAll,
                    ],
                    Self::EndpointPredicate => &[
                        PolicyRecord::CategoriesPredicate,
                        PolicyRecord::EndpointsPredicate,
                    ],
                    Self::CatalogRef | Self::CatalogRefs => &[PolicyRecord::Catalog],
                    Self::SourceEvidence => &[PolicyRecord::Evidence],
                    Self::TransferEffect => &[
                        PolicyRecord::SanitizeEffect,
                        PolicyRecord::TransformEffect,
                    ],
                    Self::SemanticEvent => &[
                        PolicyRecord::NormalProcedureExit,
                        PolicyRecord::ExceptionalProcedureExit,
                    ],
                    Self::ClassificationSpec => &[PolicyRecord::Classification],
                    Self::TaxonomyClassification | Self::Classifications => {
                        &[PolicyRecord::ClassificationId]
                    }
                    Self::ClassificationPredicate | Self::Predicates => &[
                        PolicyRecord::PredicateAll,
                        PolicyRecord::PredicateAny,
                        PolicyRecord::AnalysisTypePredicate,
                        PolicyRecord::SourceCategoriesPredicate,
                        PolicyRecord::SinkCategoriesPredicate,
                        PolicyRecord::SourceLabelsPredicate,
                        PolicyRecord::SinkTagsPredicate,
                        PolicyRecord::SinkImpactsPredicate,
                        PolicyRecord::FindingCombinationPredicate,
                        PolicyRecord::TypestateExpectationPredicate,
                    ],
                    Self::CvssEvidencePredicate | Self::CvssPredicates => &[
                        PolicyRecord::CvssPredicateAll,
                        PolicyRecord::CvssPredicateAny,
                        PolicyRecord::AnalysisTypePredicate,
                        PolicyRecord::SourceEvidence,
                        PolicyRecord::SourceCategoriesPredicate,
                        PolicyRecord::SinkCategoriesPredicate,
                        PolicyRecord::SourceLabelsPredicate,
                        PolicyRecord::SinkTagsPredicate,
                        PolicyRecord::SinkImpactsPredicate,
                    ],
                    Self::CvssPolicy => &[PolicyRecord::Cvss],
                    Self::EndpointRefs | Self::EvidenceReferences => &[PolicyRecord::EndpointRef],
                    Self::SourceEntries => &[PolicyRecord::Source],
                    Self::SinkEntries => &[PolicyRecord::Sink],
                    Self::SanitizerEntries => &[PolicyRecord::Sanitizer],
                    Self::OriginEntries => &[PolicyRecord::Origin],
                    Self::ObservationEntries => &[PolicyRecord::Observation],
                    Self::KillEntries => &[PolicyRecord::Kill],
                    Self::TransformEntries => &[PolicyRecord::TransformEntry],
                    Self::ExternalModelEntries => &[PolicyRecord::ExternalModel],
                    Self::Transfers => &[PolicyRecord::Transfer],
                    Self::FindingCombinations => &[PolicyRecord::FindingCombination],
                    Self::SubjectSet => &[PolicyRecord::SubjectSet],
                    Self::CallModelingSpec => &[PolicyRecord::CallModeling],
                    Self::UncertaintySpec => &[PolicyRecord::Uncertainty],
                    Self::AutomatonSpec => &[PolicyRecord::Automaton],
                    Self::CallsTrigger => &[PolicyRecord::Calls],
                    Self::TypestateSubjects => &[PolicyRecord::Subject],
                    Self::TypestateEvents => &[PolicyRecord::Event],
                    Self::TypestateTransitions => &[PolicyRecord::Transition],
                    Self::TerminalExpectations => &[PolicyRecord::TerminalExpectation],
                    Self::ClassificationRefinements => &[PolicyRecord::Refinement],
                    Self::CvssMetrics => &[PolicyRecord::Metric],
                    Self::AssertEntries => &[
                        PolicyRecord::Assert,
                        PolicyRecord::AssertResolution,
                        PolicyRecord::AssertBindingScope,
                        PolicyRecord::AssertValueOrigin,
                        PolicyRecord::AssertOriginShape,
                        PolicyRecord::AssertBoundary,
                        PolicyRecord::AssertGeneration,
                        PolicyRecord::AssertDeclarationState,
                        PolicyRecord::AssertEdgeParity,
                        PolicyRecord::AssertEdgeClass,
                        PolicyRecord::AssertCanonical,
                        PolicyRecord::AssertRoute,
                        PolicyRecord::AssertRoundTrip,
                        PolicyRecord::AssertFlowEstablishment,
                        PolicyRecord::AssertRewriteTermination,
                    ],
                    Self::AssertionPlanEntries => &[
                        PolicyRecord::Bind,
                        PolicyRecord::Filter,
                        PolicyRecord::Project,
                        PolicyRecord::Join,
                        PolicyRecord::Group,
                        PolicyRecord::CallArgument,
                        PolicyRecord::Call,
                        PolicyRecord::RowAssert,
                        PolicyRecord::RowAssertSelectedInWinningTier,
                    ],
                    Self::RowSelectorEntries => &[
                        PolicyRecord::Bind,
                        PolicyRecord::Filter,
                        PolicyRecord::Project,
                        PolicyRecord::Join,
                        PolicyRecord::CallArgument,
                        PolicyRecord::Call,
                    ],
                    Self::RowAggregates => &[PolicyRecord::Aggregate],
                    Self::AssertCardinality => &[
                        PolicyRecord::CardinalityExactly,
                        PolicyRecord::CardinalityAtLeast,
                        PolicyRecord::CardinalityAtMost,
                    ],
                    Self::CaptureName
                    | Self::OccurrenceRole
                    | Self::ExpectedOccurrence
                    | Self::OccurrenceNamespace
                    | Self::PrecedenceTier
                    | Self::GenerationKind
                    | Self::DeclarationOrigin
                    | Self::DeclaredContainment
                    | Self::OriginShape
                    | Self::BoundaryStrength
                    | Self::UsageSurface
                    | Self::EdgeClassAxis
                    | Self::EstablishmentRequirement
                    | Self::RewriteDomain
                    | Self::EdgeClassValues
                    | Self::RouteHop
                    | Self::Boolean
                    | Self::RowExpansionStep
                    | Self::RowJoinKind
                    | Self::RowAggregateOp => &[],
                    Self::SchemaVersion
                    | Self::PolicyId
                    | Self::EndpointId
                    | Self::LocalEntryId
                    | Self::StateId
                    | Self::EventId
                    | Self::ExpectationId
                    | Self::CombinationId
                    | Self::Name
                    | Self::DisplayText
                    | Self::Description
                    | Self::HelpUri
                    | Self::TaxonomyName
                    | Self::TaxonomyIdentifier
                    | Self::WorkspacePath
                    | Self::Sha256
                    | Self::NonNegativeInteger
                    | Self::PositiveInteger
                    | Self::AnalysisType
                    | Self::RqlQuery
                    | Self::GeneratedRelation
                    | Self::EndpointRole
                    | Self::TaintMode
                    | Self::UnmodeledCallBehavior
                    | Self::TrustBoundary
                    | Self::SystemEntry
                    | Self::DirectoryScope
                    | Self::ObservationPhase
                    | Self::InconclusivePolicy
                    | Self::ExitScope
                    | Self::CvssVersion
                    | Self::CvssEmitPolicy
                    | Self::CvssBaseMetric
                    | Self::CvssBaseMetricValue
                    | Self::CvssBasis
                    | Self::CvssScope
                    | Self::PolicyTags
                    | Self::Categories
                    | Self::EndpointIds
                    | Self::StateIds
                    | Self::EventIds
                    | Self::ExpectationIds
                    | Self::CombinationIds
                    | Self::TaintLabels
                    | Self::TaintTags
                    | Self::TaintImpacts
                    | Self::Strings
                    | Self::RowName
                    | Self::RowFieldRef
                    | Self::RowFieldRefs
                    | Self::RowJoinConditions
                    | Self::RowOrderedSequence
                    | Self::RowProjectionColumns
                    | Self::RowPredicates => &[],
                }
            }
        }
    };
}

value_shapes! {
    SchemaVersion => "a supported positive schema version",
    PolicyId => "a stable lowercase policy identifier",
    EndpointId => "a stable lowercase endpoint identifier",
    LocalEntryId => "a lowercase local entry identifier",
    StateId => "a lowercase typestate state identifier",
    EventId => "a lowercase typestate event identifier",
    ExpectationId => "a lowercase typestate expectation identifier",
    CombinationId => "a lowercase finding-combination identifier",
    Name => "a bounded human-readable name",
    DisplayText => "bounded human-readable display text",
    Message => "a static string or generated-message record",
    Description => "bounded human-readable descriptive text",
    HelpUri => "an absolute HTTP or HTTPS URI",
    TaxonomyName => "a bounded exact taxonomy name",
    TaxonomyIdentifier => "a bounded exact taxonomy identifier",
    WorkspacePath => "a validated workspace-relative path",
    Sha256 => "a lowercase 64-hex SHA-256 value",
    NonNegativeInteger => "a non-negative integer",
    PositiveInteger => "a positive integer",
    AnalysisType => "match, taint, typestate, assertion, or flow",
    CaptureName => "an RQL capture name bound by the subject selector",
    OccurrenceRole => "one occurrence role from the analyzer registry",
    ExpectedOccurrence => "declaration, reference, binding, or none",
    OccurrenceNamespace => "type, value, module, macro, or label",
    AssertCardinality => "an exactly, at-least, or at-most cardinality record",
    PrecedenceTier => "one precedence tier from the analyzer registry",
    GenerationKind => "one generation kind from the analyzer registry",
    DeclarationOrigin => "parsed, generated, or recovered",
    RouteHop => "one identity route hop kind from the analyzer registry",
    DeclaredContainment => "inside or outside",
    OriginShape => "collection-literal",
    BoundaryStrength => "external_declared_unindexed or external_unknown",
    UsageSurface => "external-usages or lsp-references",
    EdgeClassAxis => "relation, usage, site-class, or kind",
    EstablishmentRequirement => "dominated or reached",
    RewriteDomain => "one bounded rewrite domain from the analyzer registry",
    EdgeClassValues => "one or more classification labels of the constrained axis",
    AssertEntries => "assert records",
    AssertionPlanEntries => "bind, filter, project, join, group, call-argument, call, relational assert, and assert-selected-in-winning-tier records",
    RowSelectorEntries => "bind, filter, project, join, call-argument, and call records",
    RowAggregates => "aggregate records",
    RowName => "a bounded row binding, group, or aggregate name",
    RowFieldRef => "a binding.field row reference",
    RowFieldRefs => "one or more binding.field row references",
    RowJoinConditions => "one or more equality field pairs",
    RowPredicates => "zero or more typed row predicates, each (BINDING.FIELD eq|ne|lt|le|gt|ge VALUE-OR-FIELD), (BINDING.FIELD is-null|is-not-null), or (BINDING.FIELD in (VALUE...))",
    RowExpansionStep => "a registered typed row expansion",
    RowJoinKind => "inner, semi, or anti",
    RowAggregateOp => "min, max, count, count-distinct, any, all, or ordered-equal",
    RowProjectionColumns => "one or more BINDING.FIELD references, each optionally wrapped as a (BINDING.FIELD NEW-FIELD) rename",
    RowOrderedSequence => "a (POSITION-FIELD VALUE-FIELD) ordered sequence pair",
    Boolean => "true or false",
    AnalysisRecord => "an analysis record whose fields agree with its explicit type",
    ReportOptions => "a report record",
    WitnessOptions => "a witness record",
    Selector => "an inline rql or deferred rql-file selector",
    RqlQuery => "one native RQL query expression",
    Severity => "note, warning, error, unrated, or a cvss-severity record",
    FixedOrUnratedSeverity => "note, warning, error, or unrated",
    GeneratedRelation => "the can-reach generated relation",
    EndpointRole => "source or sink",
    EndpointBinding => "matched-value, receiver, return-value, or an argument record",
    EndpointSemantics => "source-semantics or sink-semantics matching the endpoint role",
    PolicyPort => "matched-value, receiver, return-value, or an argument record",
    TaintMode => "the may analysis mode",
    UnmodeledCallBehavior => "paranoid, optimistic, or require-model",
    TaintEndpointSet => "an endpoint-set record",
    MatchEndpointSet => "a match-directory or match-endpoints record",
    CategoryPredicate => "an exact any or all category predicate",
    EndpointPredicate => "a categories or endpoints predicate",
    CatalogRef => "a catalog record",
    SourceEvidence => "an evidence or source-evidence record",
    TrustBoundary => "external, internal, or same-trust-zone",
    SystemEntry => "a supported vulnerable-system entry kind",
    DirectoryScope => "direct or recursive",
    ObservationPhase => "at-match, before-call, after-normal-return, or after-exceptional-return",
    TransferEffect => "propagate, sanitize, or transform transfer semantics",
    TypestateBinding => "matched-value, receiver, return-value, or an argument record",
    TypestateCallBinding => "receiver, return-value, or an argument record",
    ExternalModelPort => "receiver, return-value, or an argument record; matched-value is forbidden",
    InconclusivePolicy => "the inconclusive uncertainty policy",
    SemanticEvent => "a normal-procedure-exit or exceptional-procedure-exit record",
    ExitScope => "the analysis-root exit scope",
    ClassificationSpec => "a classification record",
    TaxonomyClassification => "a classification-id record",
    ClassificationPredicate => "a typed classification evidence predicate",
    CvssEvidencePredicate => "a typed CVSS evidence predicate",
    CvssVersion => "the string 4.0",
    CvssEmitPolicy => "when-base-complete",
    CvssBaseMetric => "one of the eleven CVSS v4.0 Base metric names",
    CvssBaseMetricValue => "a value legal for the selected CVSS Base metric",
    CvssBasis => "policy-assertion",
    CvssScope => "vulnerable-system, subsequent-system, or global",
    CvssPolicy => "a cvss record",
    PolicyTags => "policy tags",
    Categories => "opaque exact endpoint categories",
    EndpointIds => "endpoint identifiers",
    StateIds => "typestate state identifiers",
    EventIds => "typestate event identifiers",
    ExpectationIds => "typestate expectation identifiers",
    CombinationIds => "finding-combination identifiers",
    TaintLabels => "normalized taint labels",
    TaintTags => "normalized sink tags",
    TaintImpacts => "normalized sink impacts",
    Strings => "bounded strings",
    CatalogRefs => "catalog records",
    MatchEndpointSets => "match-directory or match-endpoints records",
    EndpointRefs => "endpoint-ref records",
    SourceEntries => "policy-local source records",
    SinkEntries => "policy-local sink records",
    SanitizerEntries => "policy-local sanitizer records",
    OriginEntries => "policy-local origin records",
    ObservationEntries => "policy-local observation records",
    KillEntries => "policy-local kill records",
    TransformEntries => "policy-local transform records",
    ExternalModelEntries => "policy-local external-model records",
    Transfers => "transfer records",
    FindingCombinations => "finding-combination records",
    SubjectSet => "a subject-set record",
    CallModelingSpec => "a call-modeling record",
    UncertaintySpec => "an uncertainty record",
    AutomatonSpec => "an automaton record",
    CallsTrigger => "a calls record",
    TypestateSubjects => "subject records",
    TypestateEvents => "event records",
    TypestateTransitions => "transition records",
    TerminalExpectations => "terminal-expectation records",
    Classifications => "classification-id records",
    ClassificationRefinements => "ordered refinement records",
    Predicates => "typed evidence predicate records",
    CvssPredicates => "typed CVSS evidence predicate records",
    CvssMetrics => "CVSS metric records",
    EvidenceReferences => "policy evidence references",
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyFieldDescriptor {
    pub field: PolicyField,
    pub record: PolicyRecord,
    pub labels: &'static [&'static str],
    pub placement: FieldPlacement,
    pub occurrence: FieldOccurrence,
    pub context: FieldContextApplicability,
    /// Context to pass when this field's value contains a nested record.
    pub child_context: PolicyRecordContext,
    pub requiredness: FieldRequiredness,
    pub multiplicity: ValueMultiplicity,
    pub value_shape: PolicyValueShape,
    pub applicability: OwnerApplicability,
    pub signature: &'static str,
    pub description: &'static str,
}

macro_rules! policy_fields {
    ($($variant:ident {
        record: $record:ident,
        labels: [$($label:literal),* $(,)?],
        placement: $placement:expr,
        required: $required:ident,
        multiplicity: $multiplicity:expr,
        shape: $shape:ident,
        owner: $owner:expr,
        $(context: $context:ident,)?
        $(child_context: $child_context:ident,)?
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum PolicyField {
            $($variant,)+
        }

        pub const ALL_POLICY_FIELDS: &[PolicyFieldDescriptor] = &[
            $(PolicyFieldDescriptor {
                field: PolicyField::$variant,
                record: PolicyRecord::$record,
                labels: &[$($label),*],
                placement: $placement,
                occurrence: FieldOccurrence::Single,
                context: policy_field_context!($($context)?),
                child_context: policy_child_context!($($child_context)?),
                requiredness: FieldRequiredness::$required,
                multiplicity: $multiplicity,
                value_shape: PolicyValueShape::$shape,
                applicability: $owner,
                signature: $signature,
                description: $description,
            },)+
        ];
    };
}

macro_rules! policy_field_context {
    () => {
        FieldContextApplicability::Any
    };
    (TypestateTriggerOnly) => {
        FieldContextApplicability::TypestateTriggerOnly
    };
    (TaintSourcesOnly) => {
        FieldContextApplicability::TaintSourcesOnly
    };
    (TaintSinksOnly) => {
        FieldContextApplicability::TaintSinksOnly
    };
    (TaintSanitizersOnly) => {
        FieldContextApplicability::TaintSanitizersOnly
    };
    (TaintTransformsOnly) => {
        FieldContextApplicability::TaintTransformsOnly
    };
    (TaintExternalModelsOnly) => {
        FieldContextApplicability::TaintExternalModelsOnly
    };
    (TaintSourceOrSinkOnly) => {
        FieldContextApplicability::TaintSourceOrSinkOnly
    };
    (FlowOriginsOnly) => {
        FieldContextApplicability::FlowOriginsOnly
    };
    (FlowObservationsOnly) => {
        FieldContextApplicability::FlowObservationsOnly
    };
    (FlowKillsOnly) => {
        FieldContextApplicability::FlowKillsOnly
    };
}

macro_rules! policy_child_context {
    () => {
        PolicyRecordContext::Ordinary
    };
    ($context:ident) => {
        PolicyRecordContext::$context
    };
}

const SCALAR: ValueMultiplicity = ValueMultiplicity::Scalar;
const SET_64: ValueMultiplicity = ValueMultiplicity::set(0, 64);
const NON_EMPTY_SET_64: ValueMultiplicity = ValueMultiplicity::set(1, 64);
const SET_256: ValueMultiplicity = ValueMultiplicity::set(0, 256);
const NON_EMPTY_SET_256: ValueMultiplicity = ValueMultiplicity::set(1, 256);

policy_fields! {
    PolicySchemaVersion { record: Policy, labels: ["schema-version"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SchemaVersion, owner: OwnerApplicability::POLICY_ALL, signature: ":schema-version N", description: "Pin the RQLP version exactly; omission selects the compatible lineage head." }
    PolicyId { record: Policy, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyId, owner: OwnerApplicability::POLICY_ALL, signature: ":id \"lowercase.policy-id\"", description: "Set the stable opaque policy and SARIF rule identity." }
    PolicyName { record: Policy, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::POLICY_ALL, signature: ":name \"Human name\"", description: "Set the human-readable policy name." }
    PolicyMessage { record: Policy, labels: ["message"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Message, owner: OwnerApplicability::POLICY_ALL, signature: ":message \"text\" | (generated-message ...)", description: "Set static finding text or the taint-only generated relation." }
    PolicySeverity { record: Policy, labels: ["severity"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Severity, owner: OwnerApplicability::POLICY_ALL, signature: ":severity note|warning|error|unrated|(cvss-severity ...)", description: "Set the policy reporting severity without changing analyzer certainty." }
    PolicyDescription { record: Policy, labels: ["description"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Description, owner: OwnerApplicability::POLICY_ALL, signature: ":description \"text\"", description: "Add bounded descriptive text." }
    PolicyHelpUri { record: Policy, labels: ["help-uri"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: HelpUri, owner: OwnerApplicability::POLICY_ALL, signature: ":help-uri \"https://...\"", description: "Link to absolute HTTP(S) remediation help." }
    PolicyTags { record: Policy, labels: ["tags"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: PolicyTags, owner: OwnerApplicability::POLICY_ALL, signature: ":tags [TAG...]", description: "Attach a duplicate-free set of bounded policy tags." }
    PolicyAnalysis { record: Policy, labels: ["analysis"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: AnalysisRecord, owner: OwnerApplicability::POLICY_ALL, signature: ":analysis (analysis ...)", description: "Provide the explicitly typed diagnostic-neutral analysis declaration." }
    PolicyClassification { record: Policy, labels: ["classification"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: ClassificationSpec, owner: OwnerApplicability::POLICY_ALL, signature: ":classification (classification ...)", description: "Add broad/refined taxonomy and optional CVSS policy." }
    PolicyReport { record: Policy, labels: ["report"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: ReportOptions, owner: OwnerApplicability::POLICY_ALL, signature: ":report (report ...)", description: "Override bounded report retention defaults." }

    EndpointSchemaVersion { record: Endpoint, labels: ["schema-version"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SchemaVersion, owner: OwnerApplicability::ENDPOINT, signature: ":schema-version N", description: "Pin the endpoint document version exactly." }
    EndpointId { record: Endpoint, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EndpointId, owner: OwnerApplicability::ENDPOINT, signature: ":id \"lowercase.endpoint-id\"", description: "Set the stable endpoint identity." }
    EndpointName { record: Endpoint, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::ENDPOINT, signature: ":name \"Human name\"", description: "Set the endpoint's human-readable name." }
    EndpointDisplayName { record: Endpoint, labels: ["display-name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::ENDPOINT, signature: ":display-name \"Generated-message phrase\"", description: "Set the phrase used verbatim in generated relationship messages." }
    EndpointDescription { record: Endpoint, labels: ["description"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Description, owner: OwnerApplicability::ENDPOINT, signature: ":description \"text\"", description: "Add bounded endpoint description text." }
    EndpointHelpUri { record: Endpoint, labels: ["help-uri"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: HelpUri, owner: OwnerApplicability::ENDPOINT, signature: ":help-uri \"https://...\"", description: "Link to absolute HTTP(S) endpoint documentation." }
    EndpointRole { record: Endpoint, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EndpointRole, owner: OwnerApplicability::ENDPOINT, signature: ":role source|sink", description: "Declare whether the endpoint supplies or consumes a value." }
    EndpointCategories { record: Endpoint, labels: ["categories"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::ENDPOINT, signature: ":categories [CATEGORY...]", description: "Attach opaque exact categories for explicit set composition." }
    EndpointSelector { record: Endpoint, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::ENDPOINT, signature: ":selector (rql ...)|(rql-file ...)", description: "Select the endpoint's diagnostic-neutral code sites." }
    EndpointBinding { record: Endpoint, labels: ["binding"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EndpointBinding, owner: OwnerApplicability::ENDPOINT, signature: ":binding matched-value|receiver|return-value|(argument ...)", description: "Bind the selected matched value, receiver, return, or argument." }
    EndpointTaint { record: Endpoint, labels: ["taint"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EndpointSemantics, owner: OwnerApplicability::ENDPOINT, signature: ":taint (source-semantics ...)|(sink-semantics ...)", description: "Optionally attach role-compatible taint semantics." }
    EndpointSupersedes { record: Endpoint, labels: ["supersedes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: EndpointIds, owner: OwnerApplicability::ENDPOINT, signature: ":supersedes [ENDPOINT-ID...]", description: "Declare explicit same-event dominance edges." }

    AnalysisType { record: Analysis, labels: ["type"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: AnalysisType, owner: OwnerApplicability::POLICY_ALL, signature: ":type match|taint|typestate|assertion|flow", description: "Select the analysis variant; fields are never inferred from their presence." }
    AnalysisSubject { record: Analysis, labels: ["subject"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":subject (rql ...)|(rql-file ...)", description: "Select the subject nodes each specialized assertion is evaluated at; required with :asserts." }
    AnalysisAsserts { record: Analysis, labels: ["asserts"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::sequence(1, 64), shape: AssertEntries, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":asserts [(assert ...)...]", description: "Declare specialized occurrence, resolution, route, or identity invariants; required with :subject." }
    AnalysisPlanEntries { record: Analysis, labels: [], placement: FieldPlacement::VariadicPositional, required: Optional, multiplicity: ValueMultiplicity::sequence(1, 64), shape: AssertionPlanEntries, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(bind|filter|project|join|group|assert ...)...", description: "Declare a bounded source-ordered relational assertion plan." }
    RowSelectorOutput { record: RowSelector, labels: ["output"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::ENDPOINT_OR_POLICY_TAINT_OR_FLOW, signature: ":output NAME", description: "Name the live relation consumed as the endpoint selection output." }
    RowSelectorEntries { record: RowSelector, labels: [], placement: FieldPlacement::VariadicPositional, required: Required, multiplicity: ValueMultiplicity::sequence(1, 64), shape: RowSelectorEntries, owner: OwnerApplicability::ENDPOINT_OR_POLICY_TAINT_OR_FLOW, signature: "(bind|filter|project|join|call|call-argument ...)...", description: "Declare source-ordered typed bindings and derivations for one endpoint selector." }
    AnalysisSelector { record: Analysis, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_MATCH, signature: ":selector (rql ...)|(rql-file ...)", description: "Select positive location-bearing match results." }
    AnalysisMode { record: Analysis, labels: ["mode"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaintMode, owner: OwnerApplicability::POLICY_TAINT_TYPESTATE_OR_FLOW, signature: ":mode may", description: "Select the schema-version-1 may analysis mode." }
    AnalysisCallModeling { record: Analysis, labels: ["call-modeling"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: CallModelingSpec, owner: OwnerApplicability::POLICY_TAINT_TYPESTATE_OR_FLOW, signature: ":call-modeling (call-modeling :unmodeled paranoid|optimistic|require-model)", description: "Choose fallback behavior for unmodeled calls; omission defaults to paranoid." }
    AnalysisSources { record: Analysis, labels: ["sources"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_TAINT, child_context: TaintSources, signature: ":sources (endpoint-set ...)", description: "Compose the complete taint source set." }
    AnalysisSinks { record: Analysis, labels: ["sinks"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_TAINT, child_context: TaintSinks, signature: ":sinks (endpoint-set ...)", description: "Compose the complete taint sink set." }
    AnalysisSanitizers { record: Analysis, labels: ["sanitizers"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_TAINT, child_context: TaintSanitizers, signature: ":sanitizers (endpoint-set ...)", description: "Compose optional sanitizer models; omission is empty." }
    AnalysisTransforms { record: Analysis, labels: ["transforms"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_TAINT, child_context: TaintTransforms, signature: ":transforms (endpoint-set ...)", description: "Compose optional label transforms; omission is empty." }
    AnalysisExternalModels { record: Analysis, labels: ["external-models"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_TAINT, child_context: TaintExternalModels, signature: ":external-models (endpoint-set ...)", description: "Compose optional external transfer models; omission is empty." }
    AnalysisOrigins { record: Analysis, labels: ["origins"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_FLOW, child_context: FlowOrigins, signature: ":origins (endpoint-set :entries [(origin ...)...])", description: "Compose the complete value-flow origin set." }
    AnalysisObservations { record: Analysis, labels: ["observations"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_FLOW, child_context: FlowObservations, signature: ":observations (endpoint-set :entries [(observation ...)...])", description: "Compose the complete value-flow observation set." }
    AnalysisKills { record: Analysis, labels: ["kills"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: TaintEndpointSet, owner: OwnerApplicability::POLICY_FLOW, child_context: FlowKills, signature: ":kills (endpoint-set :entries [(kill ...)...])", description: "Compose optional value-flow kills; omission is empty." }
    AnalysisFindingCombinations { record: Analysis, labels: ["finding-combinations"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: FindingCombinations, owner: OwnerApplicability::POLICY_TAINT, signature: ":finding-combinations [(finding-combination ...)...]", description: "Declare bounded explicit presentation/classification precedence rules." }
    AnalysisSubjects { record: Analysis, labels: ["subjects"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: SubjectSet, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":subjects (subject-set ...)", description: "Compose values newly tracked by typestate." }
    AnalysisUncertainty { record: Analysis, labels: ["uncertainty"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: UncertaintySpec, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":uncertainty (uncertainty ...)", description: "Declare explicit handling for subjects that escape the analysis root." }
    AnalysisAutomaton { record: Analysis, labels: ["automaton"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: AutomatonSpec, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":automaton (automaton ...)", description: "Declare the author-facing typestate automaton and terminal obligations." }

    BindName { record: Bind, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":name NAME", description: "Set the unique row binding name." }
    BindQuery { record: Bind, labels: ["query"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":query (rql ...)|(rql-file ...)", description: "Execute one typed CodeQuery as the binding source." }
    BindFrom { record: Bind, labels: ["from"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":from NAME", description: "Name an earlier binding to expand." }
    BindStep { record: Bind, labels: ["step"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RowExpansionStep, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":step STEP", description: "Select one typed expansion relation." }
    FilterOver { record: Filter, labels: ["over"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":over NAME", description: "Name the row relation this filter narrows." }
    FilterWhere { record: Filter, labels: ["where"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::sequence(1, 16), shape: RowPredicates, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":where ((BINDING.FIELD OP VALUE)...)", description: "Conjoin bounded typed predicates a row must satisfy to stay in the relation." }
    ProjectName { record: Project, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":name NEW", description: "Set the name the projected relation publishes; it replaces the relation named by :from." }
    ProjectFrom { record: Project, labels: ["from"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":from NAME", description: "Name the row relation whose columns are projected." }
    ProjectColumns { record: Project, labels: ["columns"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::sequence(1, 32), shape: RowProjectionColumns, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":columns (BINDING.FIELD|(BINDING.FIELD NEW-FIELD)...)", description: "Choose the projected columns; a (SOURCE NEW-FIELD) pair renames one, and a bare reference keeps its field name." }
    JoinLeft { record: Join, labels: ["left"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":left NAME", description: "Name the left row binding." }
    JoinRight { record: Join, labels: ["right"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":right NAME", description: "Name the right row binding." }
    JoinKind { record: Join, labels: ["kind"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RowJoinKind, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":kind inner|semi|anti", description: "Choose an inner join, a semi join that keeps matching left rows without the right relation columns, or an anti-join that keeps left rows with no partner; omission means inner." }
    JoinOn { record: Join, labels: ["on"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::sequence(1, 16), shape: RowJoinConditions, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":on ((LEFT-FIELD RIGHT-FIELD)...)", description: "Declare equal-typed field pairs relative to the left and right bindings." }
    GroupName { record: Group, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":name NAME", description: "Set the unique row group name." }
    GroupBy { record: Group, labels: ["by"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::sequence(1, 16), shape: RowFieldRefs, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":by (BINDING.FIELD...)", description: "Choose the typed row fields that identify each group." }
    GroupAggregates { record: Group, labels: [], placement: FieldPlacement::VariadicPositional, required: Required, multiplicity: ValueMultiplicity::sequence(1, 32), shape: RowAggregates, owner: OwnerApplicability::POLICY_ASSERTION, signature: "(aggregate ...)...", description: "Declare the source-ordered aggregates computed for the group." }
    AggregateName { record: Aggregate, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":name NAME", description: "Set the unique aggregate name within its group." }
    AggregateOp { record: Aggregate, labels: ["op"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowAggregateOp, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":op min|max|count|count-distinct|any|all|ordered-equal", description: "Choose the bounded aggregate operation." }
    AggregateValue { record: Aggregate, labels: ["value"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RowFieldRef, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":value BINDING.FIELD", description: "Select the typed input field the fold reads: an integer field for min or max, a boolean field for any or all, any field for count-distinct." }
    AggregateWhere { record: Aggregate, labels: ["where"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::sequence(0, 16), shape: RowPredicates, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":where ((BINDING.FIELD OP VALUE)...)", description: "Conjoin bounded typed predicates a row must satisfy to contribute to the fold." }
    AggregateLeft { record: Aggregate, labels: ["left"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RowOrderedSequence, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":left (BINDING.POSITION BINDING.VALUE)", description: "Name the left ordered sequence of an ordered-equal aggregate: its integer position field and the value read at that position." }
    AggregateRight { record: Aggregate, labels: ["right"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RowOrderedSequence, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":right (BINDING.POSITION BINDING.VALUE)", description: "Name the right ordered sequence of an ordered-equal aggregate; its value field must have the same scalar type as the left one." }
    CallArgumentOver { record: CallArgument, labels: ["over"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":over NAME", description: "Name the call_binding relation to filter in place." }
    CallArgumentFormalName { record: CallArgument, labels: ["formal-name"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":formal-name \"NAME\"", description: "Select the exact formal declared name; mutually exclusive with formal-index." }
    CallArgumentFormalIndex { record: CallArgument, labels: ["formal-index"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":formal-index N", description: "Select the zero-based formal index; mutually exclusive with formal-name." }
    CallOver { record: Call, labels: ["over"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":over NAME", description: "Name the call_binding relation to filter in place." }
    CallResolvesTo { record: Call, labels: ["resolves-to"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":resolves-to MODEL_ID", description: "Name the stable semantic-model symbol identity; this is not a qualified display name or source spelling." }
    CallProof { record: Call, labels: ["proof"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":proof exact", description: "Require the exact dispatch proof; no weaker proof tier is accepted by this selector." }
    RowAssertId { record: RowAssert, labels: ["id"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id ID", description: "Optionally override the stable assertion identity derived from group and aggregate names." }
    RowAssertGroup { record: RowAssert, labels: ["group"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":group NAME", description: "Name the row group being asserted." }
    RowAssertValue { record: RowAssert, labels: ["value"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":value NAME", description: "Name the aggregate being asserted." }
    RowAssertCardinality { record: RowAssert, labels: ["cardinality"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: AssertCardinality, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":cardinality (exactly|at-least|at-most N)", description: "Set the expected aggregate cardinality." }
    WinningTierId { record: RowAssertSelectedInWinningTier, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id ID", description: "Set the assertion identity, which also names the row group this sugar declares." }
    WinningTierSite { record: RowAssertSelectedInWinningTier, labels: ["site"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":site NAME", description: "Name the binding holding one overload-selection row per call site." }
    WinningTierCandidates { record: RowAssertSelectedInWinningTier, labels: ["candidates"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RowName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":candidates NAME", description: "Name the binding holding the callable-applicability rows of the same sites." }
    WinningTierCardinality { record: RowAssertSelectedInWinningTier, labels: ["cardinality"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: AssertCardinality, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":cardinality (exactly|at-least|at-most N)", description: "Bound the number of candidates that are both selected and applicable; omission means exactly 1. State (exactly 0) to assert an unresolved site and (at-least 2) to assert an ambiguous one." }

    RqlSchemaVersion { record: Rql, labels: ["schema-version"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SchemaVersion, owner: OwnerApplicability::BOTH, signature: ":schema-version N", description: "Pin the nested RQL version exactly; omission uses the RQL compatible head." }
    RqlQuery { record: Rql, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: SCALAR, shape: RqlQuery, owner: OwnerApplicability::BOTH, signature: "QUERY", description: "Embed exactly one spanned RQL query subtree." }
    RqlFileSchemaVersion { record: RqlFile, labels: ["schema-version"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SchemaVersion, owner: OwnerApplicability::BOTH, signature: ":schema-version N", description: "Pin or constrain the referenced RQL document version." }
    RqlFilePath { record: RqlFile, labels: ["path"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: WorkspacePath, owner: OwnerApplicability::BOTH, signature: ":path \"queries/name.rql\"", description: "Name one workspace-root-relative RQL file for deferred loading." }

    GeneratedMessageRelation { record: GeneratedMessage, labels: ["relation"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: GeneratedRelation, owner: OwnerApplicability::POLICY_TAINT, signature: ":relation can-reach", description: "Select the fixed can-reach relation renderer." }
    CvssSeverityWhenUnscored { record: CvssSeverity, labels: ["when-unscored"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: FixedOrUnratedSeverity, owner: OwnerApplicability::POLICY_ALL, signature: ":when-unscored unrated|note|warning|error", description: "Set the fallback when no complete CVSS assessment exists." }
    ArgumentIndex { record: Argument, labels: ["index"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::BOTH, signature: ":index N", description: "Bind a zero-based argument index; mutually exclusive with name." }
    ArgumentName { record: Argument, labels: ["name"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::BOTH, signature: ":name \"formal-name\"", description: "Bind an exact formal argument name; mutually exclusive with index." }

    SourceSemanticsLabels { record: SourceSemantics, labels: ["labels"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::ENDPOINT, signature: ":labels [LABEL...]", description: "Declare the non-empty labels introduced by the endpoint." }
    SourceSemanticsEvidence { record: SourceSemantics, labels: ["evidence"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SourceEvidence, owner: OwnerApplicability::ENDPOINT, signature: ":evidence (evidence ...)", description: "Attach coherent source trust/entry evidence." }
    SinkSemanticsAccepts { record: SinkSemantics, labels: ["accepts"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::ENDPOINT, signature: ":accepts [LABEL...]", description: "Declare the non-empty labels consumed by the endpoint." }
    SinkSemanticsTags { record: SinkSemantics, labels: ["tags"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintTags, owner: OwnerApplicability::ENDPOINT, signature: ":tags [TAG...]", description: "Attach exact sink tags for evidence predicates." }
    SinkSemanticsImpacts { record: SinkSemantics, labels: ["impacts"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintImpacts, owner: OwnerApplicability::ENDPOINT, signature: ":impacts [IMPACT...]", description: "Attach exact sink impacts for evidence predicates." }
    EvidenceTrustBoundary { record: Evidence, labels: ["trust-boundary"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: TrustBoundary, owner: OwnerApplicability::BOTH, signature: ":trust-boundary external|internal|same-trust-zone", description: "Describe the source trust boundary." }
    EvidenceSystemEntry { record: Evidence, labels: ["system-entry"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SystemEntry, owner: OwnerApplicability::BOTH, signature: ":system-entry ENTRY", description: "Describe how the source enters the vulnerable system." }

    ReportWitness { record: Report, labels: ["witness"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: WitnessOptions, owner: OwnerApplicability::POLICY_ALL, signature: ":witness (witness ...)", description: "Override the per-witness bounds." }
    ReportWitnessesPerFinding { record: Report, labels: ["witnesses-per-finding"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ALL, signature: ":witnesses-per-finding N", description: "Bound retained witnesses per finding." }
    ReportOriginsPerFinding { record: Report, labels: ["origins-per-finding"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ALL, signature: ":origins-per-finding N", description: "Bound retained dependency origins per finding." }
    WitnessMaxSteps { record: Witness, labels: ["max-steps"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ALL, signature: ":max-steps N", description: "Bound retained steps in one witness." }
    WitnessMaxBytes { record: Witness, labels: ["max-bytes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ALL, signature: ":max-bytes N", description: "Bound encoded bytes in one witness." }

    EndpointSetIncludeSets { record: EndpointSet, labels: ["include-sets"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::set(0, 64), shape: CatalogRefs, owner: OwnerApplicability::POLICY_TAINT, signature: ":include-sets [(catalog ...)...]", description: "Include explicitly registered catalog endpoint sets." }
    EndpointSetIncludeMatches { record: EndpointSet, labels: ["include-matches"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::set(0, 64), shape: MatchEndpointSets, owner: OwnerApplicability::POLICY_TAINT, context: TaintSourceOrSinkOnly, signature: ":include-matches [(match-directory ...)|(match-endpoints ...)...]", description: "Include explicitly selected source or sink endpoint leaves; other taint set kinds reject this field." }
    EndpointSetSourceEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: SourceEntries, owner: OwnerApplicability::POLICY_TAINT, context: TaintSourcesOnly, signature: ":entries [(source ...)...]", description: "Add bounded policy-local source entries." }
    EndpointSetSinkEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: SinkEntries, owner: OwnerApplicability::POLICY_TAINT, context: TaintSinksOnly, signature: ":entries [(sink ...)...]", description: "Add bounded policy-local sink entries." }
    EndpointSetSanitizerEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: SanitizerEntries, owner: OwnerApplicability::POLICY_TAINT, context: TaintSanitizersOnly, signature: ":entries [(sanitizer ...)...]", description: "Add bounded policy-local sanitizer entries." }
    EndpointSetTransformEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: TransformEntries, owner: OwnerApplicability::POLICY_TAINT, context: TaintTransformsOnly, signature: ":entries [(transform ...)...]", description: "Add bounded policy-local transform entries." }
    EndpointSetOriginEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: OriginEntries, owner: OwnerApplicability::POLICY_FLOW, context: FlowOriginsOnly, signature: ":entries [(origin ...)...]", description: "Add bounded policy-local value-flow origin entries." }
    EndpointSetObservationEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: ObservationEntries, owner: OwnerApplicability::POLICY_FLOW, context: FlowObservationsOnly, signature: ":entries [(observation ...)...]", description: "Add bounded policy-local value-flow observation entries." }
    EndpointSetKillEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: KillEntries, owner: OwnerApplicability::POLICY_FLOW, context: FlowKillsOnly, signature: ":entries [(kill ...)...]", description: "Add bounded policy-local value-flow kill entries." }
    EndpointSetExternalModelEntries { record: EndpointSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: ExternalModelEntries, owner: OwnerApplicability::POLICY_TAINT, context: TaintExternalModelsOnly, signature: ":entries [(external-model ...)...]", description: "Add bounded policy-local external-model entries." }
    CatalogName { record: Catalog, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyId, owner: OwnerApplicability::POLICY_TAINT, signature: ":name \"catalog.id\"", description: "Name an explicitly registered catalog." }
    CatalogVersion { record: Catalog, labels: ["version"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PositiveInteger, owner: OwnerApplicability::POLICY_TAINT, signature: ":version N", description: "Select an exact positive catalog version." }
    CatalogSha256 { record: Catalog, labels: ["sha256"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Sha256, owner: OwnerApplicability::POLICY_TAINT, signature: ":sha256 \"64-lower-hex\"", description: "Optionally pin canonical typed catalog content." }
    MatchDirectoryPath { record: MatchDirectory, labels: ["path"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: WorkspacePath, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":path \"policies/endpoints\"", description: "Name the capability-rooted endpoint directory." }
    MatchDirectoryScope { record: MatchDirectory, labels: ["scope"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DirectoryScope, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":scope direct|recursive", description: "Choose direct children or bounded recursive traversal." }
    MatchDirectoryRole { record: MatchDirectory, labels: ["role"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EndpointRole, owner: OwnerApplicability::POLICY_TYPESTATE, context: TypestateTriggerOnly, signature: ":role source|sink", description: "Constrain a typestate endpoint trigger to one role; the decoder lifts it out of MatchDirectoryRef." }
    MatchDirectoryPhase { record: MatchDirectory, labels: ["phase"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: ObservationPhase, owner: OwnerApplicability::POLICY_TYPESTATE, context: TypestateTriggerOnly, signature: ":phase PHASE", description: "Choose the typed typestate trigger phase; the decoder lifts it out of MatchDirectoryRef." }
    MatchDirectoryCategories { record: MatchDirectory, labels: ["categories"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CategoryPredicate, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":categories (any|all [CATEGORY...])", description: "Select endpoints by exact categories." }
    MatchDirectoryManifest { record: MatchDirectory, labels: ["manifest-sha256"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Sha256, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":manifest-sha256 \"64-lower-hex\"", description: "Optionally pin the complete selected endpoint manifest." }
    MatchEndpointsIds { record: MatchEndpoints, labels: ["ids"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::set(1, 64), shape: EndpointIds, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":ids [ENDPOINT-ID...]", description: "Name a non-empty finite exact endpoint set." }
    MatchEndpointsRole { record: MatchEndpoints, labels: ["role"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EndpointRole, owner: OwnerApplicability::POLICY_TYPESTATE, context: TypestateTriggerOnly, signature: ":role source|sink", description: "Constrain a typestate exact-endpoint trigger to one role; the decoder lifts it out of the set reference." }
    MatchEndpointsPhase { record: MatchEndpoints, labels: ["phase"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: ObservationPhase, owner: OwnerApplicability::POLICY_TYPESTATE, context: TypestateTriggerOnly, signature: ":phase PHASE", description: "Choose the typed exact-endpoint trigger phase; the decoder lifts it out of the set reference." }
    CategoryAnyValues { record: CategoryAny, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "[CATEGORY...]", description: "Provide the non-empty exact category set." }
    CategoryAllValues { record: CategoryAll, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "[CATEGORY...]", description: "Provide the non-empty exact category set." }
    CategoriesPredicateAny { record: CategoriesPredicate, labels: ["any"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":any [CATEGORY...]", description: "Match at least one exact category; mutually exclusive with all." }
    CategoriesPredicateAll { record: CategoriesPredicate, labels: ["all"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":all [CATEGORY...]", description: "Match every exact category; mutually exclusive with any." }
    EndpointsPredicateValues { record: EndpointsPredicate, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: NON_EMPTY_SET_64, shape: EndpointRefs, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: "[ENDPOINT-REF...]", description: "Provide a non-empty exact endpoint reference set." }
    EndpointRefLocal { record: EndpointRef, labels: ["local"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":local \"entry-id\"", description: "Reference a policy-local endpoint entry." }
    EndpointRefCatalog { record: EndpointRef, labels: ["catalog"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: CatalogRef, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":catalog (catalog ...)", description: "Reference an endpoint in an explicitly named catalog." }
    EndpointRefEntry { record: EndpointRef, labels: ["entry"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":entry \"entry-id\"", description: "Name the catalog entry when catalog is selected." }
    EndpointRefMatch { record: EndpointRef, labels: ["match-endpoint"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EndpointId, owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, signature: ":match-endpoint \"endpoint-id\"", description: "Reference one explicitly loaded match endpoint." }

    SourceId { record: Source, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id \"entry-id\"", description: "Set the policy-local source identity." }
    SourceDisplayName { record: Source, labels: ["display-name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::POLICY_TAINT, signature: ":display-name \"phrase\"", description: "Set the generated-message phrase for this source." }
    SourceCategories { record: Source, labels: ["categories"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT, signature: ":categories [CATEGORY...]", description: "Attach exact source categories." }
    SourceSelector { record: Source, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TAINT, signature: ":selector SELECTOR", description: "Select the source sites." }
    SourceBind { record: Source, labels: ["bind"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":bind PORT", description: "Bind the source value at each selected site." }
    SourceLabels { record: Source, labels: ["labels"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":labels [LABEL...]", description: "Declare the non-empty labels introduced by the source." }
    SourceEvidenceField { record: Source, labels: ["evidence"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SourceEvidence, owner: OwnerApplicability::POLICY_TAINT, signature: ":evidence (evidence ...)", description: "Attach coherent source trust/entry evidence." }
    SinkId { record: Sink, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id \"entry-id\"", description: "Set the policy-local sink identity." }
    SinkDisplayName { record: Sink, labels: ["display-name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::POLICY_TAINT, signature: ":display-name \"phrase\"", description: "Set the generated-message phrase for this sink." }
    SinkCategories { record: Sink, labels: ["categories"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT, signature: ":categories [CATEGORY...]", description: "Attach exact sink categories." }
    SinkSelector { record: Sink, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TAINT, signature: ":selector SELECTOR", description: "Select the sink sites." }
    SinkDangerousOperand { record: Sink, labels: ["dangerous-operand"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":dangerous-operand PORT", description: "Bind the sink operand that consumes tainted data." }
    SinkAccepts { record: Sink, labels: ["accepts"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":accepts [LABEL...]", description: "Declare the non-empty labels accepted by the sink." }
    SinkTags { record: Sink, labels: ["tags"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintTags, owner: OwnerApplicability::POLICY_TAINT, signature: ":tags [TAG...]", description: "Attach exact sink tags." }
    SinkImpacts { record: Sink, labels: ["impacts"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintImpacts, owner: OwnerApplicability::POLICY_TAINT, signature: ":impacts [IMPACT...]", description: "Attach exact sink impacts." }
    OriginId { record: Origin, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_FLOW, signature: ":id \"entry-id\"", description: "Set the policy-local origin identity." }
    OriginDisplayName { record: Origin, labels: ["display-name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::POLICY_FLOW, signature: ":display-name \"phrase\"", description: "Set the reported phrase for this origin." }
    OriginSelector { record: Origin, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_FLOW, signature: ":selector SELECTOR", description: "Select the origin sites." }
    OriginBind { record: Origin, labels: ["bind"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_FLOW, signature: ":bind PORT", description: "Bind the established value at each selected origin site." }
    ObservationId { record: Observation, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_FLOW, signature: ":id \"entry-id\"", description: "Set the policy-local observation identity." }
    ObservationDisplayName { record: Observation, labels: ["display-name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::POLICY_FLOW, signature: ":display-name \"phrase\"", description: "Set the reported phrase for this observation." }
    ObservationSelector { record: Observation, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_FLOW, signature: ":selector SELECTOR", description: "Select the observation sites." }
    ObservationOperand { record: Observation, labels: ["observed-operand"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_FLOW, signature: ":observed-operand PORT", description: "Bind the operand whose value the observation consumes." }
    KillId { record: Kill, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_FLOW, signature: ":id \"entry-id\"", description: "Set the policy-local kill identity." }
    KillSelector { record: Kill, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_FLOW, signature: ":selector SELECTOR", description: "Select the kill sites." }
    KillInput { record: Kill, labels: ["input"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_FLOW, signature: ":input PORT", description: "Bind the value the kill consumes." }
    KillOutput { record: Kill, labels: ["output"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_FLOW, signature: ":output PORT", description: "Bind the value the kill establishes; it no longer carries the tracked provenance." }
    SanitizerId { record: Sanitizer, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id \"entry-id\"", description: "Set the sanitizer identity." }
    SanitizerSelector { record: Sanitizer, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TAINT, signature: ":selector SELECTOR", description: "Select sanitizer calls or values." }
    SanitizerInput { record: Sanitizer, labels: ["input"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":input PORT", description: "Bind the sanitizer input value." }
    SanitizerOutput { record: Sanitizer, labels: ["output"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":output PORT", description: "Bind the sanitizer output value." }
    SanitizerRemoves { record: Sanitizer, labels: ["removes"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":removes [LABEL...]", description: "Declare the non-empty labels removed by the sanitizer." }
    TransformId { record: TransformEntry, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id \"entry-id\"", description: "Set the transform identity." }
    TransformSelector { record: TransformEntry, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TAINT, signature: ":selector SELECTOR", description: "Select transform calls or values." }
    TransformInput { record: TransformEntry, labels: ["input"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":input PORT", description: "Bind the transform input value." }
    TransformOutput { record: TransformEntry, labels: ["output"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PolicyPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":output PORT", description: "Bind the transform output value." }
    TransformRemoves { record: TransformEntry, labels: ["removes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":removes [LABEL...]", description: "Declare labels removed by the transform." }
    TransformAdds { record: TransformEntry, labels: ["adds"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":adds [LABEL...]", description: "Declare labels added by the transform; removes and adds cannot both be empty." }
    ExternalModelId { record: ExternalModel, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id \"entry-id\"", description: "Set the external model identity." }
    ExternalModelSelector { record: ExternalModel, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TAINT, signature: ":selector SELECTOR", description: "Select the modeled external calls." }
    ExternalModelTransfers { record: ExternalModel, labels: ["transfers"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::set(1, 256), shape: Transfers, owner: OwnerApplicability::POLICY_TAINT, signature: ":transfers [(transfer ...)...]", description: "Declare a duplicate-free semantic set of typed port transfers." }
    TransferFrom { record: Transfer, labels: ["from"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExternalModelPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":from receiver|return-value|(argument ...)", description: "Bind the transfer input call port; matched-value is forbidden." }
    TransferTo { record: Transfer, labels: ["to"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExternalModelPort, owner: OwnerApplicability::POLICY_TAINT, signature: ":to receiver|return-value|(argument ...)", description: "Bind the transfer output call port; matched-value is forbidden." }
    TransferLabels { record: Transfer, labels: ["labels"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":labels [LABEL...]", description: "Select the non-empty labels affected by this transfer." }
    TransferEffectField { record: Transfer, labels: ["effect"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TransferEffect, owner: OwnerApplicability::POLICY_TAINT, signature: ":effect propagate|(sanitize ...)|(transform ...)", description: "Choose propagation, sanitization, or transformation." }
    SanitizeEffectRemoves { record: SanitizeEffect, labels: ["removes"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":removes [LABEL...]", description: "Declare the non-empty labels removed by the effect." }
    TransformEffectRemoves { record: TransformEffect, labels: ["removes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":removes [LABEL...]", description: "Declare labels removed by the effect." }
    TransformEffectAdds { record: TransformEffect, labels: ["adds"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":adds [LABEL...]", description: "Declare labels added by the effect; removes and adds cannot both be empty." }

    CombinationId { record: FindingCombination, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CombinationId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id \"combination-id\"", description: "Set the stable combination identity." }
    CombinationSource { record: FindingCombination, labels: ["source"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EndpointPredicate, owner: OwnerApplicability::POLICY_TAINT, signature: ":source (categories ...)|(endpoints ...)", description: "Select the finite source endpoint identities covered by this rule." }
    CombinationSink { record: FindingCombination, labels: ["sink"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EndpointPredicate, owner: OwnerApplicability::POLICY_TAINT, signature: ":sink (categories ...)|(endpoints ...)", description: "Select the finite sink endpoint identities covered by this rule." }
    CombinationMessage { record: FindingCombination, labels: ["message"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::POLICY_TAINT, signature: ":message \"static text\"", description: "Replace the generic message for the winning combination." }
    CombinationSeverity { record: FindingCombination, labels: ["severity"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Severity, owner: OwnerApplicability::POLICY_TAINT, signature: ":severity SEVERITY", description: "Optionally replace the policy severity for this combination." }
    CombinationClassifications { record: FindingCombination, labels: ["add-classifications"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: Classifications, owner: OwnerApplicability::POLICY_TAINT, signature: ":add-classifications [(classification-id ...)...]", description: "Add taxonomy classifications for the winning combination." }
    CombinationSupersedes { record: FindingCombination, labels: ["supersedes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: CombinationIds, owner: OwnerApplicability::POLICY_TAINT, signature: ":supersedes [COMBINATION-ID...]", description: "Declare explicit presentation precedence over other combinations." }

    SubjectSetIncludeMatches { record: SubjectSet, labels: ["include-matches"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::set(0, 64), shape: MatchEndpointSets, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":include-matches [MATCH-SET...]", description: "Include source endpoint leaves as newly tracked subjects." }
    SubjectSetEntries { record: SubjectSet, labels: ["entries"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: TypestateSubjects, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":entries [(subject ...)...]", description: "Add policy-local subject seed selectors." }
    SubjectId { record: Subject, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":id \"subject-id\"", description: "Set the policy-local subject identity." }
    SubjectSelector { record: Subject, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":selector SELECTOR", description: "Select values that begin typestate tracking." }
    SubjectBinding { record: Subject, labels: ["subject"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TypestateBinding, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":subject BINDING", description: "Bind the newly tracked value." }
    CallModelingUnmodeled { record: CallModeling, labels: ["unmodeled"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: UnmodeledCallBehavior, owner: OwnerApplicability::POLICY_TAINT_TYPESTATE_OR_FLOW, signature: ":unmodeled paranoid|optimistic|require-model", description: "Choose conservative propagation, preserve-only propagation, or abstention when no call model applies." }
    UncertaintyEscape { record: Uncertainty, labels: ["escape"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: InconclusivePolicy, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":escape inconclusive", description: "Mark subjects escaping the analysis root as incomplete." }
    AutomatonStates { record: Automaton, labels: ["states"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_256, shape: StateIds, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":states [STATE...]", description: "Declare every typestate state." }
    AutomatonInitial { record: Automaton, labels: ["initial"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: StateId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":initial STATE", description: "Select the declared initial state." }
    AutomatonAccepting { record: Automaton, labels: ["accepting-states"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_256, shape: StateIds, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":accepting-states [STATE...]", description: "Declare non-absorbing states that satisfy terminal expectations." }
    AutomatonErrors { record: Automaton, labels: ["error-states"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_256, shape: StateIds, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":error-states [STATE...]", description: "Declare states whose transitions produce policy violations." }
    AutomatonEvents { record: Automaton, labels: ["events"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_256, shape: TypestateEvents, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":events [(event ...)...]", description: "Declare the bounded typed event set." }
    AutomatonTransitions { record: Automaton, labels: ["transitions"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::set(1, 4096), shape: TypestateTransitions, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":transitions [(transition ...)...]", description: "Declare deterministic state/event transitions." }
    AutomatonExpectations { record: Automaton, labels: ["terminal-expectations"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_256, shape: TerminalExpectations, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":terminal-expectations [(terminal-expectation ...)...]", description: "Declare explicit or implicit terminal accepting-state obligations." }
    EventIdField { record: Event, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EventId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":id EVENT", description: "Set the stable event identity." }
    EventCalls { record: Event, labels: ["calls"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: CallsTrigger, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":calls (calls ...)", description: "Trigger on a direct selector call; exclusive with matches and on." }
    EventMatches { record: Event, labels: ["matches"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: MatchEndpointSet, owner: OwnerApplicability::POLICY_TYPESTATE, child_context: TypestateTrigger, signature: ":matches MATCH-SET", description: "Trigger on selected endpoint observations; exclusive with calls and on." }
    EventOn { record: Event, labels: ["on"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SemanticEvent, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":on SEMANTIC-EVENT", description: "Trigger on an implicit semantic event; exclusive with calls and matches." }
    EventAppliesTo { record: Event, labels: ["applies-to-subjects"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EndpointPredicate, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":applies-to-subjects ENDPOINT-PREDICATE", description: "Restrict the event to a finite resolved subject set." }
    EventSupersedes { record: Event, labels: ["supersedes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: EventIds, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":supersedes [EVENT...]", description: "Declare explicit same-observation event dominance." }
    CallsSelector { record: Calls, labels: ["selector"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: Selector, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":selector SELECTOR", description: "Select direct call observations." }
    CallsSubject { record: Calls, labels: ["subject"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TypestateCallBinding, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":subject receiver|return-value|(argument ...)", description: "Bind the already tracked object at the call." }
    CallsPhase { record: Calls, labels: ["phase"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ObservationPhase, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":phase PHASE", description: "Observe before the call or after a specific continuation." }
    TransitionFrom { record: Transition, labels: ["from"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: StateId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":from STATE", description: "Name the declared source state." }
    TransitionOn { record: Transition, labels: ["on"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EventId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":on EVENT", description: "Name the declared triggering event." }
    TransitionTo { record: Transition, labels: ["to"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: StateId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":to STATE", description: "Name the declared destination state." }
    ExpectationIdField { record: TerminalExpectation, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExpectationId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":id EXPECTATION", description: "Set the stable expectation identity." }
    ExpectationMatches { record: TerminalExpectation, labels: ["matches"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: MatchEndpointSet, owner: OwnerApplicability::POLICY_TYPESTATE, child_context: TypestateTrigger, signature: ":matches MATCH-SET", description: "Observe an explicit endpoint terminal; exclusive with on." }
    ExpectationOn { record: TerminalExpectation, labels: ["on"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SemanticEvent, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":on SEMANTIC-EVENT", description: "Observe normal or exceptional analysis-root exit; exclusive with matches." }
    ExpectationAppliesTo { record: TerminalExpectation, labels: ["applies-to-subjects"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EndpointPredicate, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":applies-to-subjects ENDPOINT-PREDICATE", description: "Restrict the expectation to a finite resolved subject set." }
    ExpectationStates { record: TerminalExpectation, labels: ["expected-states"], placement: FieldPlacement::Keyword, required: Required, multiplicity: NON_EMPTY_SET_256, shape: StateIds, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":expected-states [ACCEPTING-STATE...]", description: "Name the non-empty accepting-state subset required at the terminal." }
    ExpectationSupersedes { record: TerminalExpectation, labels: ["supersedes"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SET_64, shape: ExpectationIds, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":supersedes [EXPECTATION...]", description: "Declare explicit same-terminal expectation dominance." }
    NormalExitScope { record: NormalProcedureExit, labels: ["scope"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExitScope, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":scope analysis-root", description: "Limit the implicit normal terminal to the outer analysis root." }
    ExceptionalExitScope { record: ExceptionalProcedureExit, labels: ["scope"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExitScope, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":scope analysis-root", description: "Limit the implicit exceptional terminal to the outer analysis root." }

    ClassificationFallback { record: Classification, labels: ["fallback"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaxonomyClassification, owner: OwnerApplicability::POLICY_ALL, signature: ":fallback (classification-id ...)", description: "Preserve one broad taxonomy classification for every finding." }
    ClassificationRefinements { record: Classification, labels: ["refinements"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::sequence(0, 128), shape: ClassificationRefinements, owner: OwnerApplicability::POLICY_ALL, signature: ":refinements [(refinement ...)...]", description: "Apply bounded refinements in source order." }
    ClassificationCvss { record: Classification, labels: ["cvss"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: CvssPolicy, owner: OwnerApplicability::POLICY_ALL, signature: ":cvss (cvss ...)", description: "Optionally establish evidence-backed CVSS Base metrics." }
    ClassificationIdTaxonomy { record: ClassificationId, labels: ["taxonomy"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaxonomyName, owner: OwnerApplicability::POLICY_ALL, signature: ":taxonomy \"NAME\"", description: "Name the taxonomy exactly." }
    ClassificationIdIdentifier { record: ClassificationId, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: TaxonomyIdentifier, owner: OwnerApplicability::POLICY_ALL, signature: ":id \"IDENTIFIER\"", description: "Name the taxonomy identifier exactly." }
    ClassificationIdName { record: ClassificationId, labels: ["name"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Name, owner: OwnerApplicability::POLICY_ALL, signature: ":name \"Display name\"", description: "Add optional taxonomy display text." }
    RefinementWhen { record: Refinement, labels: ["when"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ClassificationPredicate, owner: OwnerApplicability::POLICY_ALL, signature: ":when PREDICATE", description: "Select complete typed evidence for this refinement." }
    RefinementAdd { record: Refinement, labels: ["add"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::set(1, 64), shape: Classifications, owner: OwnerApplicability::POLICY_ALL, signature: ":add [(classification-id ...)...]", description: "Add a non-empty duplicate-free classification set." }
    PredicateAllValues { record: PredicateAll, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: ValueMultiplicity::set(1, 256), shape: Predicates, owner: OwnerApplicability::POLICY_ALL, signature: "[PREDICATE...]", description: "Provide the non-empty duplicate-free child predicate set." }
    PredicateAnyValues { record: PredicateAny, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: ValueMultiplicity::set(1, 256), shape: Predicates, owner: OwnerApplicability::POLICY_ALL, signature: "[PREDICATE...]", description: "Provide the non-empty duplicate-free child predicate set." }
    CvssPredicateAllValues { record: CvssPredicateAll, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: ValueMultiplicity::set(1, 256), shape: CvssPredicates, owner: OwnerApplicability::POLICY_ALL, signature: "[CVSS-EVIDENCE-PREDICATE...]", description: "Provide the non-empty duplicate-free child CVSS evidence predicate set." }
    CvssPredicateAnyValues { record: CvssPredicateAny, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: ValueMultiplicity::set(1, 256), shape: CvssPredicates, owner: OwnerApplicability::POLICY_ALL, signature: "[CVSS-EVIDENCE-PREDICATE...]", description: "Provide the non-empty duplicate-free child CVSS evidence predicate set." }
    AnalysisTypeIs { record: AnalysisTypePredicate, labels: ["is"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: AnalysisType, owner: OwnerApplicability::POLICY_ALL, signature: ":is match|taint|typestate", description: "Match one exact analysis kind." }
    SourceCategoriesAny { record: SourceCategoriesPredicate, labels: ["any"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT, signature: ":any [CATEGORY...]", description: "Match any listed source category; exclusive with all." }
    SourceCategoriesAll { record: SourceCategoriesPredicate, labels: ["all"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT, signature: ":all [CATEGORY...]", description: "Match all listed source categories; exclusive with any." }
    SinkCategoriesAny { record: SinkCategoriesPredicate, labels: ["any"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT, signature: ":any [CATEGORY...]", description: "Match any listed sink category; exclusive with all." }
    SinkCategoriesAll { record: SinkCategoriesPredicate, labels: ["all"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: Categories, owner: OwnerApplicability::POLICY_TAINT, signature: ":all [CATEGORY...]", description: "Match all listed sink categories; exclusive with any." }
    SourceLabelsAny { record: SourceLabelsPredicate, labels: ["any"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":any [LABEL...]", description: "Match any listed source label; exclusive with all." }
    SourceLabelsAll { record: SourceLabelsPredicate, labels: ["all"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: TaintLabels, owner: OwnerApplicability::POLICY_TAINT, signature: ":all [LABEL...]", description: "Match all listed source labels; exclusive with any." }
    SinkTagsAny { record: SinkTagsPredicate, labels: ["any"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: TaintTags, owner: OwnerApplicability::POLICY_TAINT, signature: ":any [TAG...]", description: "Match any listed sink tag; exclusive with all." }
    SinkTagsAll { record: SinkTagsPredicate, labels: ["all"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: TaintTags, owner: OwnerApplicability::POLICY_TAINT, signature: ":all [TAG...]", description: "Match all listed sink tags; exclusive with any." }
    SinkImpactsAny { record: SinkImpactsPredicate, labels: ["any"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: TaintImpacts, owner: OwnerApplicability::POLICY_TAINT, signature: ":any [IMPACT...]", description: "Match any listed sink impact; exclusive with all." }
    SinkImpactsAll { record: SinkImpactsPredicate, labels: ["all"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: NON_EMPTY_SET_64, shape: TaintImpacts, owner: OwnerApplicability::POLICY_TAINT, signature: ":all [IMPACT...]", description: "Match all listed sink impacts; exclusive with any." }
    FindingCombinationPredicateId { record: FindingCombinationPredicate, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CombinationId, owner: OwnerApplicability::POLICY_TAINT, signature: ":id COMBINATION", description: "Match one selected finding-combination ID." }
    TypestateExpectationPredicateId { record: TypestateExpectationPredicate, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExpectationId, owner: OwnerApplicability::POLICY_TYPESTATE, signature: ":id EXPECTATION", description: "Match one violated terminal-expectation ID." }

    CvssVersionField { record: Cvss, labels: ["version"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssVersion, owner: OwnerApplicability::POLICY_ALL, signature: ":version \"4.0\"", description: "Select the only schema-version-1 CVSS authoring version." }
    CvssEmit { record: Cvss, labels: ["emit"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssEmitPolicy, owner: OwnerApplicability::POLICY_ALL, signature: ":emit when-base-complete", description: "Emit a score only when all Base metrics are established coherently." }
    CvssMetricRules { record: Cvss, labels: ["metric-rules"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::sequence(1, 256), shape: CvssMetrics, owner: OwnerApplicability::POLICY_ALL, signature: ":metric-rules [(metric ...)...]", description: "Declare non-empty bounded evidence-backed Base metric rules." }
    MetricName { record: Metric, labels: ["name"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssBaseMetric, owner: OwnerApplicability::POLICY_ALL, signature: ":name AV|AC|AT|PR|UI|VC|VI|VA|SC|SI|SA", description: "Name one authorable CVSS v4.0 Base metric." }
    MetricValue { record: Metric, labels: ["value"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssBaseMetricValue, owner: OwnerApplicability::POLICY_ALL, signature: ":value LEGAL-BASE-VALUE", description: "Set a value legal for the selected Base metric; X is never authorable." }
    MetricWhen { record: Metric, labels: ["when"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssEvidencePredicate, owner: OwnerApplicability::POLICY_ALL, signature: ":when PREDICATE", description: "Select complete typed evidence that establishes the metric." }
    MetricBasis { record: Metric, labels: ["basis"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssBasis, owner: OwnerApplicability::POLICY_ALL, signature: ":basis policy-assertion", description: "Declare the only authorable static evidence basis." }
    MetricScope { record: Metric, labels: ["scope"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CvssScope, owner: OwnerApplicability::POLICY_ALL, signature: ":scope vulnerable-system|subsequent-system|global", description: "Name the system scope required by the selected metric." }
    MetricEvidenceRefs { record: Metric, labels: ["evidence-refs"], placement: FieldPlacement::Keyword, required: Required, multiplicity: ValueMultiplicity::set(1, 64), shape: EvidenceReferences, owner: OwnerApplicability::POLICY_ALL, signature: ":evidence-refs [EVIDENCE-REF...]", description: "Cite a non-empty set of resolvable typed evidence facts." }
    MetricRationale { record: Metric, labels: ["rationale"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DisplayText, owner: OwnerApplicability::POLICY_ALL, signature: ":rationale \"text\"", description: "Explain the static metric assertion." }
    MetricAssumptions { record: Metric, labels: ["assumptions"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: ValueMultiplicity::set(0, 64), shape: Strings, owner: OwnerApplicability::POLICY_ALL, signature: ":assumptions [\"text\"...]", description: "Record bounded explicit assumptions without changing evidence identity rules." }
    AssertId { record: Assert, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    AssertAt { record: Assert, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose AST node the occurrence rows are joined to; it must capture the identifier token itself, never its enclosing declaration." }
    AssertRole { record: Assert, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the asserted occurrence role; capability reporting narrows to exactly this role." }
    AssertExpect { record: Assert, labels: ["expect"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: ExpectedOccurrence, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":expect declaration|reference|binding|none", description: "Name the expected occurrence class, or none to forbid any occurrence at the role." }
    AssertCardinality { record: Assert, labels: ["cardinality"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: AssertCardinality, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":cardinality (exactly N)|(at-least N)|(at-most N)", description: "Bound the joined row count; omission means exactly 1, and :expect none means exactly 0." }
    AssertNamespace { record: Assert, labels: ["namespace"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: OccurrenceNamespace, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":namespace NAMESPACE", description: "Additionally require the joined rows to resolve in one naming space." }
    AssertRequireTarget { record: Assert, labels: ["require-target"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":require-target true|false", description: "Count only reference-class rows whose semantic target resolved; omission is false." }
    ResolutionAssertId { record: AssertResolution, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    ResolutionAssertAt { record: AssertResolution, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose reference the candidate rows are joined to; it must capture the identifier token itself." }
    ResolutionAssertRole { record: AssertResolution, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the reference-class occurrence role being resolved; capability reporting narrows to exactly this role." }
    ResolutionExpectTier { record: AssertResolution, labels: ["expect-tier"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PrecedenceTier, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":expect-tier TIER", description: "Name the precedence tier the selected candidate must sit at." }
    ResolutionAtLeast { record: AssertResolution, labels: ["at-least"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at-least true|false", description: "Accept any tier at least as strong as the expected one; omission requires the exact tier." }
    ResolutionForbidTier { record: AssertResolution, labels: ["forbid-tier"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: PrecedenceTier, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":forbid-tier TIER", description: "Forbid any selection at one named tier, which is how the anti-fallback contract is spelled." }
    ResolutionRequireUnique { record: AssertResolution, labels: ["require-unique"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":require-unique true|false", description: "Require exactly one selected candidate, making ambiguity a violation rather than a silent pick; omission is false." }
    CanonicalAssertId { record: AssertCanonical, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    CanonicalAssertAt { record: AssertCanonical, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose resolved declarations carry the first canonical identity." }
    CanonicalAssertRole { record: AssertCanonical, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the subject token's reference-class occurrence role; capability reporting narrows to exactly this role." }
    CanonicalAssertEquals { record: AssertCanonical, labels: ["equals"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":equals CAPTURE", description: "Name the second capture whose resolved declarations carry the compared canonical identity." }
    CanonicalAssertEqualsRole { record: AssertCanonical, labels: ["equals-role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":equals-role ROLE", description: "Name the second token's occurrence role." }
    CanonicalAssertDistinct { record: AssertCanonical, labels: ["distinct"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":distinct true|false", description: "Invert the requirement: the two selections must share no canonical identity; omission requires a shared one." }
    RouteAssertId { record: AssertRoute, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    RouteAssertAt { record: AssertRoute, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose site the route starts from." }
    RouteAssertRole { record: AssertRoute, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the subject token's occurrence role; capability reporting narrows to exactly this role." }
    RouteAssertTo { record: AssertRoute, labels: ["to"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":to CAPTURE", description: "Name the capture whose resolved declaration the route must terminate at." }
    RouteAssertToRole { record: AssertRoute, labels: ["to-role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":to-role ROLE", description: "Name the target token's occurrence role." }
    RouteAssertVia { record: AssertRoute, labels: ["via"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RouteHop, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":via HOP", description: "Require at least one hop of this kind on the route." }
    RouteAssertForbid { record: AssertRoute, labels: ["forbid"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: RouteHop, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":forbid HOP", description: "Never follow hops of this kind, so a route needing one does not exist for this assert." }
    RoundTripAssertId { record: AssertRoundTrip, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    RoundTripAssertAt { record: AssertRoundTrip, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose site is round-tripped." }
    RoundTripAssertRole { record: AssertRoundTrip, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the subject token's occurrence role; capability reporting narrows to exactly this role." }
    BindingScopeAssertId { record: AssertBindingScope, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    BindingScopeAssertAt { record: AssertBindingScope, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose binding-of answer is asserted about." }
    BindingScopeAssertRole { record: AssertBindingScope, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the reference-class occurrence role being reached from; capability reporting narrows to exactly this role." }
    BindingScopeDeclared { record: AssertBindingScope, labels: ["declared"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DeclaredContainment, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":declared inside|outside", description: "Require the binding's declaring scope to be contained, or not contained, in the related capture." }
    BindingScopeRelativeTo { record: AssertBindingScope, labels: ["relative-to"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":relative-to CAPTURE", description: "Name the second subject capture whose node interval the declaring scope is compared against." }
    ValueOriginAssertId { record: AssertValueOrigin, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    ValueOriginAssertAt { record: AssertValueOrigin, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose value origin is asserted about." }
    ValueOriginAssertRole { record: AssertValueOrigin, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the reference-class occurrence role being reached from; capability reporting narrows to exactly this role." }
    ValueOriginEstablished { record: AssertValueOrigin, labels: ["established"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: DeclaredContainment, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":established inside|outside", description: "Require the value's origin -- its binding's declaring scope, or an assignment reaching that binding -- to be contained, or not contained, in the related capture." }
    ValueOriginRelativeTo { record: AssertValueOrigin, labels: ["relative-to"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":relative-to CAPTURE", description: "Name the second subject capture whose node interval the value origins are compared against." }
    OriginShapeAssertId { record: AssertOriginShape, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    OriginShapeAssertAt { record: AssertOriginShape, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the captured loop whose iterated expression's origin shape is asserted about. The loop joins to its iterated expression internally; a loop that does not iterate an expression in evidence (a while loop, a counting for) violates rather than abstaining." }
    OriginShapeAssertAnchor { record: AssertOriginShape, labels: ["anchor"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":anchor CAPTURE", description: "Name the capture the finding anchors to, so two subject matches sharing one iterated expression stay distinct findings. Must be bound by every selector alternative." }
    OriginShapeAssertRole { record: AssertOriginShape, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the reference-class occurrence role the origin join reads from; capability reporting narrows to exactly this role." }
    OriginShapeAssertShape { record: AssertOriginShape, labels: ["shape"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OriginShape, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":shape collection-literal", description: "Name the required origin shape. The only shape today is collection-literal: an array, list, set, dictionary, or tuple display literal." }
    OriginShapeAssertMaxElements { record: AssertOriginShape, labels: ["max-elements"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: PositiveInteger, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":max-elements N", description: "Bound the qualifying literal's element count. A literal with more elements does not satisfy the assert." }
    BoundaryAssertId { record: AssertBoundary, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    BoundaryAssertAt { record: AssertBoundary, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture whose reference the candidate rows are joined to." }
    BoundaryAssertRole { record: AssertBoundary, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the reference-class occurrence role being resolved; capability reporting narrows to exactly this role." }
    BoundaryForbidFallbackPast { record: AssertBoundary, labels: ["forbid-fallback-past"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: BoundaryStrength, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":forbid-fallback-past external_declared_unindexed|external_unknown", description: "Name the boundary strength at or past which a name-only fallback selection is forbidden." }
    GenerationAssertId { record: AssertGeneration, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    GenerationAssertAt { record: AssertGeneration, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture addressing the generation site node itself." }
    GenerationAssertKind { record: AssertGeneration, labels: ["kind"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: GenerationKind, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":kind KIND", description: "Restrict the joined site rows to one generation kind." }
    GenerationAssertCardinality { record: AssertGeneration, labels: ["cardinality"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: AssertCardinality, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":cardinality (exactly N)", description: "Require the literal site's generated set to satisfy this cardinality." }
    GenerationAssertForbidDynamic { record: AssertGeneration, labels: ["forbid-dynamic"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":forbid-dynamic true|false", description: "Report a dynamic generation site as a finding instead of an inconclusive verdict." }
    DeclarationStateAssertId { record: AssertDeclarationState, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    DeclarationStateAssertAt { record: AssertDeclarationState, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture addressing the declaration node whose state is asserted." }
    DeclarationStateAssertOrigin { record: AssertDeclarationState, labels: ["origin"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: DeclarationOrigin, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":origin ORIGIN", description: "Require the state row's origin to be exactly this value." }
    DeclarationStateAssertDeclarationOnly { record: AssertDeclarationState, labels: ["declaration-only"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":declaration-only true|false", description: "Require the state row's declaration-only flag to match." }
    DeclarationStateAssertConfigGated { record: AssertDeclarationState, labels: ["config-gated"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":config-gated true|false", description: "Require the state row's configuration gate to match." }
    EdgeParityId { record: AssertEdgeParity, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    EdgeParityAt { record: AssertEdgeParity, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture; it must capture the identifier token whose edges are compared." }
    EdgeParityRole { record: AssertEdgeParity, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "A reference-class role compares forward to inverse; declaration_name compares the declaration's inverse listing to forward." }
    EdgeParitySurface { record: AssertEdgeParity, labels: ["surface"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: UsageSurface, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":surface external-usages|lsp-references", description: "Compare only edges of one usage surface; omission compares the complete row set." }
    EdgeClassId { record: AssertEdgeClass, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    EdgeClassAt { record: AssertEdgeClass, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture; it must capture the identifier token whose edges are classified." }
    EdgeClassRole { record: AssertEdgeClass, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "A reference-class role reads the token's forward edges; declaration_name reads the declaration's inverse listing." }
    EdgeClassAxisField { record: AssertEdgeClass, labels: ["axis"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: EdgeClassAxis, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":axis relation|usage|site-class|kind", description: "Name the classification axis the constraint applies to." }
    EdgeClassRequire { record: AssertEdgeClass, labels: ["require"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EdgeClassValues, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":require [value ...]", description: "Every edge's value on the axis must be one of these labels." }
    EdgeClassForbid { record: AssertEdgeClass, labels: ["forbid"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EdgeClassValues, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":forbid [value ...]", description: "No edge's value on the axis may be one of these labels." }
    EdgeClassSurface { record: AssertEdgeClass, labels: ["surface"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: UsageSurface, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":surface external-usages|lsp-references", description: "Classify only edges of one usage surface; omission classifies the complete row set." }
    FlowEstablishmentId { record: AssertFlowEstablishment, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    FlowEstablishmentAt { record: AssertFlowEstablishment, labels: ["at"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":at CAPTURE", description: "Name the subject capture; it must capture the identifier token whose read is asserted about." }
    FlowEstablishmentRole { record: AssertFlowEstablishment, labels: ["role"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: OccurrenceRole, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":role ROLE", description: "Name the occurrence role the read is spelled at; capability reporting narrows to exactly this role." }
    FlowEstablishmentRequire { record: AssertFlowEstablishment, labels: ["require"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: EstablishmentRequirement, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":require dominated|reached", description: "Require an establishment on some path (reached, the default) or on every entry-to-read path (dominated)." }
    FlowEstablishmentForbidSameEvaluation { record: AssertFlowEstablishment, labels: ["forbid-same-evaluation"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: Boolean, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":forbid-same-evaluation true|false", description: "Additionally forbid an establishment from serving a read inside its own evaluation." }
    RewriteTerminationId { record: AssertRewriteTermination, labels: ["id"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: LocalEntryId, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":id \"assert-id\"", description: "Set the stable assertion identity used by finding anchors and messages." }
    RewriteTerminationDomain { record: AssertRewriteTermination, labels: ["domain"], placement: FieldPlacement::Keyword, required: Required, multiplicity: SCALAR, shape: RewriteDomain, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":domain DOMAIN", description: "Name the declared finite rewrite domain whose chases must converge." }
    RewriteTerminationScope { record: AssertRewriteTermination, labels: ["scope"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: CaptureName, owner: OwnerApplicability::POLICY_ASSERTION, signature: ":scope CAPTURE", description: "Narrow the file set to the files whose subject rows bind this capture; omission states the domain terminates on every analyzed file." }
    CardinalityExactlyValue { record: CardinalityExactly, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ASSERTION, signature: "N", description: "Provide the exact required row count." }
    CardinalityAtLeastValue { record: CardinalityAtLeast, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ASSERTION, signature: "N", description: "Provide the inclusive lower bound on the row count." }
    CardinalityAtMostValue { record: CardinalityAtMost, labels: [], placement: FieldPlacement::Positional { index: 0 }, required: Required, multiplicity: SCALAR, shape: NonNegativeInteger, owner: OwnerApplicability::POLICY_ASSERTION, signature: "N", description: "Provide the inclusive upper bound on the row count." }

    SourceEvidenceTrustBoundary { record: SourceEvidence, labels: ["trust-boundary"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: TrustBoundary, owner: OwnerApplicability::POLICY_TAINT, signature: ":trust-boundary external|internal|same-trust-zone", description: "Match the trust boundary on one coherent source fact." }
    SourceEvidenceSystemEntry { record: SourceEvidence, labels: ["system-entry"], placement: FieldPlacement::Keyword, required: Optional, multiplicity: SCALAR, shape: SystemEntry, owner: OwnerApplicability::POLICY_TAINT, signature: ":system-entry ENTRY", description: "Match the system entry on the same coherent source fact." }
}

pub fn fields_for_record(
    record: PolicyRecord,
) -> impl Iterator<Item = &'static PolicyFieldDescriptor> {
    ALL_POLICY_FIELDS
        .iter()
        .filter(move |descriptor| descriptor.record == record)
}

pub fn applicable_fields_for_record(
    record: PolicyRecord,
    document: RqlpDocumentKind,
    analysis: Option<PolicyAnalysisKind>,
    context: PolicyRecordContext,
) -> impl Iterator<Item = &'static PolicyFieldDescriptor> {
    fields_for_record(record).filter(move |descriptor| {
        descriptor.applicability.allows(document, analysis) && descriptor.context.allows(context)
    })
}

pub fn lookup_field(record: PolicyRecord, label: &str) -> Option<&'static PolicyFieldDescriptor> {
    let label = label.strip_prefix(':').unwrap_or(label);
    fields_for_record(record).find(|descriptor| descriptor.labels.contains(&label))
}

pub fn lookup_applicable_field(
    record: PolicyRecord,
    label: &str,
    document: RqlpDocumentKind,
    analysis: Option<PolicyAnalysisKind>,
    context: PolicyRecordContext,
) -> Option<&'static PolicyFieldDescriptor> {
    let label = label.strip_prefix(':').unwrap_or(label);
    applicable_fields_for_record(record, document, analysis, context)
        .find(|descriptor| descriptor.labels.contains(&label))
}

pub fn required_fields_for_record(
    record: PolicyRecord,
    document: RqlpDocumentKind,
    analysis: Option<PolicyAnalysisKind>,
    context: PolicyRecordContext,
) -> impl Iterator<Item = &'static PolicyFieldDescriptor> {
    applicable_fields_for_record(record, document, analysis, context)
        .filter(|descriptor| descriptor.requiredness == FieldRequiredness::Required)
}

pub fn positional_field(record: PolicyRecord, index: u8) -> Option<&'static PolicyFieldDescriptor> {
    fields_for_record(record)
        .find(|descriptor| descriptor.placement == FieldPlacement::Positional { index })
}

pub fn variadic_positional_field(record: PolicyRecord) -> Option<&'static PolicyFieldDescriptor> {
    fields_for_record(record)
        .find(|descriptor| descriptor.placement == FieldPlacement::VariadicPositional)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtomDomain {
    AnalysisType,
    GeneratedRelation,
    Severity,
    EndpointRole,
    Port,
    CallPort,
    TaintMode,
    UnmodeledCallBehavior,
    TrustBoundary,
    SystemEntry,
    DirectoryScope,
    TransferEffect,
    Uncertainty,
    ObservationPhase,
    ExitScope,
    CvssVersion,
    CvssEmit,
    CvssBasis,
    CvssScope,
    EvidenceRef,
    OccurrenceRole,
    ExpectedOccurrence,
    OccurrenceNamespace,
    PrecedenceTier,
    GenerationKind,
    DeclarationOrigin,
    DeclaredContainment,
    OriginShape,
    BoundaryStrength,
    UsageSurface,
    EdgeClassAxis,
    EstablishmentRequirement,
    RewriteDomain,
    RouteHop,
    Boolean,
    RowExpansionStep,
    RowJoinKind,
    RowAggregateOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomSpellingMatch {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomValueDescriptor {
    pub value: PolicyAtomValue,
    pub domain: AtomDomain,
    pub spellings: &'static [&'static str],
    pub spelling_match: AtomSpellingMatch,
    pub applicability: OwnerApplicability,
    pub description: &'static str,
}

impl AtomValueDescriptor {
    pub fn matches(self, spelling: &str) -> bool {
        match self.spelling_match {
            AtomSpellingMatch::Exact => self.spellings.contains(&spelling),
            AtomSpellingMatch::Prefix => self
                .spellings
                .iter()
                .any(|prefix| spelling.starts_with(prefix)),
        }
    }

    pub fn matched_suffix(self, spelling: &str) -> Option<&str> {
        if self.spelling_match != AtomSpellingMatch::Prefix {
            return None;
        }
        self.spellings
            .iter()
            .find_map(|prefix| spelling.strip_prefix(prefix))
    }
}

macro_rules! atom_spelling_match {
    () => {
        AtomSpellingMatch::Exact
    };
    (Prefix) => {
        AtomSpellingMatch::Prefix
    };
}

macro_rules! atom_values {
    ($($variant:ident {
        domain: $domain:ident,
        spellings: [$primary:literal $(, $alias:literal)* $(,)?],
        $(spelling_match: $spelling_match:ident,)?
        owner: $owner:expr,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum PolicyAtomValue {
            $($variant,)+
        }

        pub const ALL_POLICY_ATOM_VALUES: &[AtomValueDescriptor] = &[
            $(AtomValueDescriptor {
                value: PolicyAtomValue::$variant,
                domain: AtomDomain::$domain,
                spellings: &[$primary $(, $alias)*],
                spelling_match: atom_spelling_match!($($spelling_match)?),
                applicability: $owner,
                description: $description,
            },)+
        ];
    };
}

atom_values! {
    AnalysisMatch { domain: AnalysisType, spellings: ["match"], owner: OwnerApplicability::POLICY_MATCH, description: "Execute a direct location-bearing selector." }
    AnalysisTaint { domain: AnalysisType, spellings: ["taint"], owner: OwnerApplicability::POLICY_TAINT, description: "Declare set-oriented taint propagation inputs." }
    AnalysisTypestate { domain: AnalysisType, spellings: ["typestate"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Declare endpoint-bound protocol tracking." }
    AnalysisAssertion { domain: AnalysisType, spellings: ["assertion"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Declare correlated occurrence invariants over captured AST nodes." }
    AnalysisFlow { domain: AnalysisType, spellings: ["flow"], owner: OwnerApplicability::POLICY_FLOW, description: "Declare policy-authored generic bounded value flow." }
    RelationCanReach { domain: GeneratedRelation, spellings: ["can-reach"], owner: OwnerApplicability::POLICY_TAINT, description: "Render source display, can reach, and sink display after proven flow." }
    SeverityUnrated { domain: Severity, spellings: ["unrated"], owner: OwnerApplicability::POLICY_ALL, description: "Do not assign a fixed report level." }
    SeverityNote { domain: Severity, spellings: ["note"], owner: OwnerApplicability::POLICY_ALL, description: "Report at note level." }
    SeverityWarning { domain: Severity, spellings: ["warning"], owner: OwnerApplicability::POLICY_ALL, description: "Report at warning level." }
    SeverityError { domain: Severity, spellings: ["error"], owner: OwnerApplicability::POLICY_ALL, description: "Report at error level." }
    EndpointSource { domain: EndpointRole, spellings: ["source"], owner: OwnerApplicability::BOTH, description: "The endpoint introduces or identifies a tracked value." }
    EndpointSink { domain: EndpointRole, spellings: ["sink"], owner: OwnerApplicability::BOTH, description: "The endpoint consumes or observes a tracked value." }
    PortMatchedValue { domain: Port, spellings: ["matched-value"], owner: OwnerApplicability::BOTH, description: "Bind the location-bearing value selected directly by non-call RQL." }
    PortReceiver { domain: Port, spellings: ["receiver"], owner: OwnerApplicability::BOTH, description: "Bind the call receiver." }
    PortReturnValue { domain: Port, spellings: ["return-value"], owner: OwnerApplicability::BOTH, description: "Bind the normal return value." }
    CallPortReceiver { domain: CallPort, spellings: ["receiver"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Bind the already tracked call receiver." }
    CallPortReturnValue { domain: CallPort, spellings: ["return-value"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Bind the already tracked normal return value." }
    ModeMay { domain: TaintMode, spellings: ["may"], owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, description: "Report flows or protocol paths that may occur." }
    UnmodeledCallParanoid { domain: UnmodeledCallBehavior, spellings: ["paranoid"], owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, description: "Conservatively propagate every transfer justified by structured call-site metadata." }
    UnmodeledCallOptimistic { domain: UnmodeledCallBehavior, spellings: ["optimistic"], owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, description: "Preserve existing facts without adding flows through the unseen body." }
    UnmodeledCallRequireModel { domain: UnmodeledCallBehavior, spellings: ["require-model"], owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, description: "Abstain from input-dependent transfer when no exact or curated model applies." }
    TrustExternal { domain: TrustBoundary, spellings: ["external"], owner: OwnerApplicability::BOTH, description: "The value crosses an external trust boundary." }
    TrustInternal { domain: TrustBoundary, spellings: ["internal"], owner: OwnerApplicability::BOTH, description: "The value originates inside the system trust boundary." }
    TrustSameZone { domain: TrustBoundary, spellings: ["same-trust-zone"], owner: OwnerApplicability::BOTH, description: "The value remains in the same trust zone." }
    EntryNetworkStack { domain: SystemEntry, spellings: ["vulnerable-system-network-stack"], owner: OwnerApplicability::BOTH, description: "The value enters through the vulnerable system network stack." }
    EntryDownloadedArtifact { domain: SystemEntry, spellings: ["downloaded-artifact"], owner: OwnerApplicability::BOTH, description: "The value enters through a downloaded artifact." }
    EntryLocalInput { domain: SystemEntry, spellings: ["local-input"], owner: OwnerApplicability::BOTH, description: "The value enters through local input." }
    EntryAdjacentNetwork { domain: SystemEntry, spellings: ["adjacent-network"], owner: OwnerApplicability::BOTH, description: "The value enters from an adjacent network." }
    EntryPhysical { domain: SystemEntry, spellings: ["physical"], owner: OwnerApplicability::BOTH, description: "The value requires physical access." }
    ScopeDirect { domain: DirectoryScope, spellings: ["direct"], owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, description: "Inspect only direct directory children." }
    ScopeRecursive { domain: DirectoryScope, spellings: ["recursive"], owner: OwnerApplicability::POLICY_TAINT_OR_TYPESTATE, description: "Inspect the bounded subtree recursively." }
    EffectPropagate { domain: TransferEffect, spellings: ["propagate"], owner: OwnerApplicability::POLICY_TAINT, description: "Propagate the selected labels unchanged." }
    UncertaintyInconclusive { domain: Uncertainty, spellings: ["inconclusive"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Mark the policy run incomplete rather than assuming behavior." }
    PhaseAtMatch { domain: ObservationPhase, spellings: ["at-match"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Observe a direct matched value." }
    PhaseBeforeCall { domain: ObservationPhase, spellings: ["before-call"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Observe the bound value before call execution." }
    PhaseAfterNormal { domain: ObservationPhase, spellings: ["after-normal-return"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Observe after the normal continuation." }
    PhaseAfterExceptional { domain: ObservationPhase, spellings: ["after-exceptional-return"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Observe after the exceptional continuation." }
    ExitAnalysisRoot { domain: ExitScope, spellings: ["analysis-root"], owner: OwnerApplicability::POLICY_TYPESTATE, description: "Observe only the outer demand procedure, not helper returns." }
    CvssV4 { domain: CvssVersion, spellings: ["4.0"], owner: OwnerApplicability::POLICY_ALL, description: "Use CVSS version 4.0." }
    CvssWhenComplete { domain: CvssEmit, spellings: ["when-base-complete"], owner: OwnerApplicability::POLICY_ALL, description: "Score only a coherent complete Base vector." }
    CvssPolicyAssertion { domain: CvssBasis, spellings: ["policy-assertion"], owner: OwnerApplicability::POLICY_ALL, description: "Establish a static metric from verified policy evidence." }
    CvssVulnerableSystem { domain: CvssScope, spellings: ["vulnerable-system"], owner: OwnerApplicability::POLICY_ALL, description: "The metric concerns the vulnerable system." }
    CvssSubsequentSystem { domain: CvssScope, spellings: ["subsequent-system"], owner: OwnerApplicability::POLICY_ALL, description: "The metric concerns a subsequent system." }
    CvssGlobal { domain: CvssScope, spellings: ["global"], owner: OwnerApplicability::POLICY_ALL, description: "The metric is global rather than system-scoped." }
    EvidencePolicySelf { domain: EvidenceRef, spellings: ["policy:self"], owner: OwnerApplicability::POLICY_ALL, description: "Reference the policy assertion itself." }
    EvidenceSelector { domain: EvidenceRef, spellings: ["selector:"], spelling_match: Prefix, owner: OwnerApplicability::POLICY_ALL, description: "Reference one stable selector semantic path." }
    RoleDeclarationName { domain: OccurrenceRole, spellings: ["declaration_name"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The name token of a declaration head." }
    RoleBinder { domain: OccurrenceRole, spellings: ["binder"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A pure binding introduction." }
    RoleLabelOrKey { domain: OccurrenceRole, spellings: ["label_or_key"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A label, keyword-argument name, or keyed-field position." }
    RoleTypeOperand { domain: OccurrenceRole, spellings: ["type_operand"], owner: OwnerApplicability::POLICY_ASSERTION, description: "An identifier consumed as a type." }
    RolePathSegment { domain: OccurrenceRole, spellings: ["path_segment"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A non-terminal segment of a qualified path." }
    RoleImportAlias { domain: OccurrenceRole, spellings: ["import_alias"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The locally introduced alias name in an import or export." }
    RoleImportTarget { domain: OccurrenceRole, spellings: ["import_target"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The imported or exported source name." }
    RoleReceiverPosition { domain: OccurrenceRole, spellings: ["receiver_position"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The receiver of a member access or call." }
    RoleMemberPosition { domain: OccurrenceRole, spellings: ["member_position"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The member name in a member access or call." }
    RolePatternPosition { domain: OccurrenceRole, spellings: ["pattern_position"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A non-binding identifier inside a pattern." }
    RoleGeneratedSource { domain: OccurrenceRole, spellings: ["generated_source"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A token whose presence generates declarations elsewhere." }
    RoleValueReference { domain: OccurrenceRole, spellings: ["value_reference"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A plain read or write of a value in expression position." }
    ExpectDeclaration { domain: ExpectedOccurrence, spellings: ["declaration"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Require declaration-class rows at the asserted role." }
    ExpectReference { domain: ExpectedOccurrence, spellings: ["reference"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Require reference-class rows at the asserted role." }
    ExpectBinding { domain: ExpectedOccurrence, spellings: ["binding"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Require binding-class rows at the asserted role." }
    ExpectNone { domain: ExpectedOccurrence, spellings: ["none"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Forbid any occurrence at the asserted role." }
    NamespaceType { domain: OccurrenceNamespace, spellings: ["type"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The type naming space." }
    NamespaceValue { domain: OccurrenceNamespace, spellings: ["value"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The value naming space." }
    NamespaceModule { domain: OccurrenceNamespace, spellings: ["module"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The module naming space." }
    NamespaceMacro { domain: OccurrenceNamespace, spellings: ["macro"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The macro naming space." }
    NamespaceLabel { domain: OccurrenceNamespace, spellings: ["label"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The label naming space." }
    GenerationAccessorMacro { domain: GenerationKind, spellings: ["accessor_macro"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A member-generating attribute macro such as attr_accessor." }
    GenerationAliasMacro { domain: GenerationKind, spellings: ["alias_macro"], owner: OwnerApplicability::POLICY_ASSERTION, description: "An alias-generating call such as alias_method." }
    GenerationPreprocessorDefinition { domain: GenerationKind, spellings: ["preprocessor_definition"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A #define that materializes a macro unit." }
    OriginParsed { domain: DeclarationOrigin, spellings: ["parsed"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Extracted from its own declaration node in a clean parse." }
    OriginGenerated { domain: DeclarationOrigin, spellings: ["generated"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Materialized by a macro-like construct with no declaration node of its own." }
    OriginRecovered { domain: DeclarationOrigin, spellings: ["recovered"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Reconstructed from a broken parse by analyzer recovery." }
    TierLexicalBinding { domain: PrecedenceTier, spellings: ["lexical_binding"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A binding introduced by the lexical environment." }
    TierOwnMember { domain: PrecedenceTier, spellings: ["own_member"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A member declared by the enclosing type itself." }
    TierInheritedMember { domain: PrecedenceTier, spellings: ["inherited_member"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A member inherited from a supertype." }
    TierExplicitImport { domain: PrecedenceTier, spellings: ["explicit_import"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A name introduced by an explicit single-name import." }
    TierPackageOrModule { domain: PrecedenceTier, spellings: ["package_or_module"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A name reachable in the same package or module." }
    TierWildcardImport { domain: PrecedenceTier, spellings: ["wildcard_import"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A name introduced by an on-demand or wildcard import." }
    TierExternalRoot { domain: PrecedenceTier, spellings: ["external_root"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A name reached through an external declaration root." }
    TierNameOnlyFallback { domain: PrecedenceTier, spellings: ["name_only_fallback"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A selection made by bare-name scan after structured routes were available." }
    DeclaredInside { domain: DeclaredContainment, spellings: ["inside"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The declaring scope is contained in the named capture." }
    DeclaredOutside { domain: DeclaredContainment, spellings: ["outside"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The declaring scope is not contained in the named capture." }
    OriginShapeCollectionLiteral { domain: OriginShape, spellings: ["collection-literal"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A collection display literal: an array, list, set, dictionary, or tuple literal." }
    BoundaryDeclaredUnindexed { domain: BoundaryStrength, spellings: ["external_declared_unindexed"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The lookup reached an external root the build declares but nothing indexed." }
    SurfaceExternalUsages { domain: UsageSurface, spellings: ["external-usages", "external_usages"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Compare only edges the external-usage surface counts." }
    SurfaceLspReferences { domain: UsageSurface, spellings: ["lsp-references", "lsp_references"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Compare every editor-visible edge, imports and self receivers included." }
    EdgeAxisRelation { domain: EdgeClassAxis, spellings: ["relation"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Constrain the owner relation between the site's encloser and the target." }
    EdgeAxisUsage { domain: EdgeClassAxis, spellings: ["usage"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Constrain the usage kind of the edge." }
    EdgeAxisSiteClass { domain: EdgeClassAxis, spellings: ["site-class", "site_class"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Constrain whether the site is a use site or a declaration site." }
    EdgeAxisKind { domain: EdgeClassAxis, spellings: ["kind"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Constrain the structured source-reference kind of the edge." }
    BoundaryUnknown { domain: BoundaryStrength, spellings: ["external_unknown"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The lookup reached ground nothing is known about." }
    RequireReached { domain: EstablishmentRequirement, spellings: ["reached"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Some control-flow path carries an establishment to the read." }
    RequireDominated { domain: EstablishmentRequirement, spellings: ["dominated"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Every entry-to-read path passes an establishment." }
    RewriteDomainRustImportAlias { domain: RewriteDomain, spellings: ["rust-import-alias", "rust_import_alias"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The Rust import-alias specifier chase, keyed on the specifier root and bounded by the importing file's binder root count." }
    HopAlias { domain: RouteHop, spellings: ["alias"], owner: OwnerApplicability::POLICY_ASSERTION, description: "A local respelling of a declaration: an import alias or a type alias." }
    HopImport { domain: RouteHop, spellings: ["import"], owner: OwnerApplicability::POLICY_ASSERTION, description: "An import binding that brings a declaration's name into a file or scope." }
    HopExport { domain: RouteHop, spellings: ["export"], owner: OwnerApplicability::POLICY_ASSERTION, description: "An export site that makes a local declaration reachable from outside its file or module." }
    HopReExport { domain: RouteHop, spellings: ["re_export"], owner: OwnerApplicability::POLICY_ASSERTION, description: "An export whose subject comes from elsewhere, forwarding identity onward." }
    HopPartialPart { domain: RouteHop, spellings: ["partial_part"], owner: OwnerApplicability::POLICY_ASSERTION, description: "One physical part of a declaration source spells in several pieces." }
    HopDeclarationDefinitionPeer { domain: RouteHop, spellings: ["declaration_definition_peer"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The peer link between a declaration head and its definition body." }
    HopNestedOwner { domain: RouteHop, spellings: ["nested_owner"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The projection from a nested declaration onto its owner." }
    HopImplementation { domain: RouteHop, spellings: ["implementation"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The link from an abstract member to a concrete member implementing it." }
    HopGeneratedPeer { domain: RouteHop, spellings: ["generated_peer"], owner: OwnerApplicability::POLICY_ASSERTION, description: "The link between a synthetic declaration and its source declaration." }
    BooleanTrue { domain: Boolean, spellings: ["true"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Enable the flag." }
    BooleanFalse { domain: Boolean, spellings: ["false"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Disable the flag." }
    RowReceiverOutcome { domain: RowExpansionStep, spellings: ["receiver-outcome"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a site into its mandatory receiver outcome row." }
    RowReceiverEvidence { domain: RowExpansionStep, spellings: ["receiver-evidence"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a site into receiver evidence rows." }
    RowMemberSelection { domain: RowExpansionStep, spellings: ["member-selection"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a site into its mandatory member selection outcome row." }
    RowMemberCandidates { domain: RowExpansionStep, spellings: ["member-candidates"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a site into member candidate rows." }
    RowCandidateHierarchy { domain: RowExpansionStep, spellings: ["candidate-hierarchy"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a member candidate into hierarchy hop rows." }
    RowMemberFamily { domain: RowExpansionStep, spellings: ["member-family"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a member into its canonical family outcome." }
    RowFamilyEdges { domain: RowExpansionStep, spellings: ["family-edges"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a member family into exact relation edges." }
    RowDispatchOutcome { domain: RowExpansionStep, spellings: ["dispatch-outcome"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a call site into its mandatory dispatch outcome row." }
    RowDispatchTargets { domain: RowExpansionStep, spellings: ["dispatch-targets"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Expand a call site into bounded dispatch target rows." }
    RowJoinInner { domain: RowJoinKind, spellings: ["inner"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Retain rows with matching right-side rows." }
    RowJoinSemi { domain: RowJoinKind, spellings: ["semi"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Retain left rows that have at least one matching right-side row, without carrying the right relation columns." }
    RowJoinAnti { domain: RowJoinKind, spellings: ["anti"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Retain left rows with no matching right-side row." }
    RowAggregateMin { domain: RowAggregateOp, spellings: ["min"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Compute the minimum integer value." }
    RowAggregateCount { domain: RowAggregateOp, spellings: ["count"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Count retained rows." }
    RowAggregateCountDistinct { domain: RowAggregateOp, spellings: ["count-distinct"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Count distinct non-null typed values." }
    RowAggregateMax { domain: RowAggregateOp, spellings: ["max"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Compute the maximum integer value." }
    RowAggregateAny { domain: RowAggregateOp, spellings: ["any"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Fold a boolean column to one when some contributing row is true, and to zero otherwise." }
    RowAggregateAll { domain: RowAggregateOp, spellings: ["all"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Fold a boolean column to one when every contributing row is true, and to zero otherwise. A group with no contributing row folds to one." }
    RowAggregateOrderedEqual { domain: RowAggregateOp, spellings: ["ordered-equal"], owner: OwnerApplicability::POLICY_ASSERTION, description: "Compare two ordered row sequences position by position: one when they hold the same value at every position and have the same length, zero otherwise." }
}

pub fn atom_values(domain: AtomDomain) -> impl Iterator<Item = &'static AtomValueDescriptor> {
    ALL_POLICY_ATOM_VALUES
        .iter()
        .filter(move |descriptor| descriptor.domain == domain)
}

pub fn lookup_atom(domain: AtomDomain, spelling: &str) -> Option<&'static AtomValueDescriptor> {
    atom_values(domain).find(|descriptor| descriptor.matches(spelling))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssBaseMetricSchema {
    Av,
    Ac,
    At,
    Pr,
    Ui,
    Vc,
    Vi,
    Va,
    Sc,
    Si,
    Sa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssMetricScopeSchema {
    VulnerableSystem,
    SubsequentSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CvssBaseMetricDescriptor {
    pub metric: CvssBaseMetricSchema,
    pub spelling: &'static str,
    pub legal_values: &'static [CvssMetricValueToken],
    pub scope: CvssMetricScopeSchema,
    pub description: &'static str,
}

macro_rules! cvss_base_metrics {
    ($($variant:ident {
        spelling: $spelling:literal,
        values: [$($value:ident),+ $(,)?],
        scope: $scope:ident,
        description: $description:literal $(,)?
    })+) => {
        pub const ALL_CVSS_BASE_METRICS: &[CvssBaseMetricDescriptor] = &[
            $(CvssBaseMetricDescriptor {
                metric: CvssBaseMetricSchema::$variant,
                spelling: $spelling,
                legal_values: &[$(CvssMetricValueToken::$value),+],
                scope: CvssMetricScopeSchema::$scope,
                description: $description,
            },)+
        ];
    };
}

cvss_base_metrics! {
    Av { spelling: "AV", values: [N, A, L, P], scope: VulnerableSystem, description: "Attack Vector." }
    Ac { spelling: "AC", values: [L, H], scope: VulnerableSystem, description: "Attack Complexity." }
    At { spelling: "AT", values: [N, P], scope: VulnerableSystem, description: "Attack Requirements." }
    Pr { spelling: "PR", values: [N, L, H], scope: VulnerableSystem, description: "Privileges Required." }
    Ui { spelling: "UI", values: [N, P, A], scope: VulnerableSystem, description: "User Interaction." }
    Vc { spelling: "VC", values: [H, L, N], scope: VulnerableSystem, description: "Vulnerable System Confidentiality." }
    Vi { spelling: "VI", values: [H, L, N], scope: VulnerableSystem, description: "Vulnerable System Integrity." }
    Va { spelling: "VA", values: [H, L, N], scope: VulnerableSystem, description: "Vulnerable System Availability." }
    Sc { spelling: "SC", values: [H, L, N], scope: SubsequentSystem, description: "Subsequent System Confidentiality." }
    Si { spelling: "SI", values: [H, L, N], scope: SubsequentSystem, description: "Subsequent System Integrity." }
    Sa { spelling: "SA", values: [H, L, N], scope: SubsequentSystem, description: "Subsequent System Availability." }
}

pub fn lookup_cvss_base_metric(spelling: &str) -> Option<&'static CvssBaseMetricDescriptor> {
    ALL_CVSS_BASE_METRICS
        .iter()
        .find(|descriptor| descriptor.spelling == spelling)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::schema_version::SchemaVersionOrigin;
    use std::collections::HashSet;

    #[test]
    fn policy_schema_version_one_is_the_compatible_head_and_exact_pin() {
        let inferred = resolve_policy_schema_version(None).unwrap();
        assert_eq!(inferred.version, POLICY_SCHEMA_VERSION);
        assert_eq!(inferred.origin, SchemaVersionOrigin::ImplicitCompatible);

        let explicit = resolve_policy_schema_version(Some(1)).unwrap();
        assert_eq!(explicit.version, POLICY_SCHEMA_VERSION);
        assert_eq!(explicit.origin, SchemaVersionOrigin::Explicit);
        assert!(resolve_policy_schema_version(Some(2)).is_err());
    }

    #[test]
    fn every_record_and_field_has_help_and_signatures() {
        for record in ALL_POLICY_RECORDS {
            assert!(!record.labels().is_empty(), "{record:?}");
            assert!(!record.signature().is_empty(), "{record:?}");
            assert!(!record.description().is_empty(), "{record:?}");
            assert!(fields_for_record(*record).next().is_some(), "{record:?}");
        }
        for field in ALL_POLICY_FIELDS {
            assert!(!field.signature.is_empty(), "{:?}", field.field);
            assert!(!field.description.is_empty(), "{:?}", field.field);
            assert!(!field.value_shape.description().is_empty());
            assert_eq!(field.occurrence, FieldOccurrence::Single);
            if field.placement == FieldPlacement::Keyword {
                assert!(!field.labels.is_empty(), "{:?}", field.field);
            }
        }
    }

    #[test]
    fn field_spellings_and_positions_are_unique_within_each_record() {
        for record in ALL_POLICY_RECORDS {
            for context in [
                PolicyRecordContext::Ordinary,
                PolicyRecordContext::TaintSources,
                PolicyRecordContext::TaintSinks,
                PolicyRecordContext::TaintSanitizers,
                PolicyRecordContext::TaintTransforms,
                PolicyRecordContext::TaintExternalModels,
                PolicyRecordContext::FlowOrigins,
                PolicyRecordContext::FlowObservations,
                PolicyRecordContext::FlowKills,
                PolicyRecordContext::TypestateTrigger,
            ] {
                let mut labels = HashSet::new();
                let mut positions = HashSet::new();
                let mut has_variadic = false;
                for field in fields_for_record(*record)
                    .filter(|descriptor| descriptor.context.allows(context))
                {
                    match field.placement {
                        FieldPlacement::Keyword => {
                            for label in field.labels {
                                assert!(
                                    labels.insert(*label),
                                    "duplicate {label} in {record:?}/{context:?}"
                                );
                            }
                        }
                        FieldPlacement::Positional { index } => {
                            assert!(
                                positions.insert(index),
                                "duplicate position {index} in {record:?}/{context:?}"
                            );
                        }
                        FieldPlacement::VariadicPositional => {
                            assert!(
                                !has_variadic,
                                "duplicate variadic field in {record:?}/{context:?}"
                            );
                            has_variadic = true;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn lookup_is_record_contextual_and_accepts_colon_prefixed_keywords() {
        assert_eq!(
            lookup_field(PolicyRecord::Policy, ":id").unwrap().field,
            PolicyField::PolicyId
        );
        assert_eq!(
            lookup_field(PolicyRecord::Endpoint, "id").unwrap().field,
            PolicyField::EndpointId
        );
        assert!(lookup_field(PolicyRecord::Rql, "path").is_none());
        assert_eq!(
            positional_field(PolicyRecord::Rql, 0).unwrap().field,
            PolicyField::RqlQuery
        );
    }

    #[test]
    fn context_sensitive_record_spellings_keep_all_candidates() {
        let transforms = records_from_label("transform").collect::<Vec<_>>();
        assert_eq!(
            transforms,
            vec![PolicyRecord::TransformEntry, PolicyRecord::TransformEffect]
        );

        let all = records_from_label("all").collect::<Vec<_>>();
        assert_eq!(
            all,
            vec![
                PolicyRecord::CategoryAll,
                PolicyRecord::PredicateAll,
                PolicyRecord::CvssPredicateAll,
            ]
        );

        assert_eq!(
            PolicyValueShape::ClassificationPredicate.accepted_records()[0],
            PolicyRecord::PredicateAll
        );
        assert_eq!(
            PolicyValueShape::CvssEvidencePredicate.accepted_records()[0],
            PolicyRecord::CvssPredicateAll
        );
    }

    #[test]
    fn applicability_rejects_fields_owned_by_another_analysis() {
        let selector = lookup_field(PolicyRecord::Analysis, "selector").unwrap();
        assert!(
            selector
                .applicability
                .allows(RqlpDocumentKind::Policy, Some(PolicyAnalysisKind::Match))
        );
        assert!(
            !selector
                .applicability
                .allows(RqlpDocumentKind::Policy, Some(PolicyAnalysisKind::Taint))
        );

        let sources = lookup_field(PolicyRecord::Analysis, "sources").unwrap();
        assert!(
            sources
                .applicability
                .allows(RqlpDocumentKind::Policy, Some(PolicyAnalysisKind::Taint))
        );
        assert!(!sources.applicability.allows(
            RqlpDocumentKind::Policy,
            Some(PolicyAnalysisKind::Typestate)
        ));

        assert!(
            lookup_applicable_field(
                PolicyRecord::Analysis,
                "sources",
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Match),
                PolicyRecordContext::Ordinary,
            )
            .is_none()
        );
        assert_eq!(
            required_fields_for_record(
                PolicyRecord::Analysis,
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Typestate),
                PolicyRecordContext::Ordinary,
            )
            .map(|field| field.field)
            .collect::<Vec<_>>(),
            vec![
                PolicyField::AnalysisType,
                PolicyField::AnalysisMode,
                PolicyField::AnalysisSubjects,
                PolicyField::AnalysisUncertainty,
                PolicyField::AnalysisAutomaton,
            ]
        );

        assert_eq!(
            applicable_records_from_label("endpoint", RqlpDocumentKind::Endpoint, None)
                .collect::<Vec<_>>(),
            vec![PolicyRecord::Endpoint]
        );

        assert!(
            lookup_applicable_field(
                PolicyRecord::MatchDirectory,
                "role",
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Taint),
                PolicyRecordContext::Ordinary,
            )
            .is_none()
        );
        assert!(
            lookup_applicable_field(
                PolicyRecord::MatchDirectory,
                "phase",
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Typestate),
                PolicyRecordContext::Ordinary,
            )
            .is_none()
        );
        assert_eq!(
            lookup_applicable_field(
                PolicyRecord::MatchDirectory,
                "phase",
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Typestate),
                PolicyRecordContext::TypestateTrigger,
            )
            .unwrap()
            .field,
            PolicyField::MatchDirectoryPhase
        );

        assert_eq!(
            lookup_field(PolicyRecord::Analysis, "sources")
                .unwrap()
                .child_context,
            PolicyRecordContext::TaintSources
        );
        assert_eq!(
            lookup_applicable_field(
                PolicyRecord::EndpointSet,
                "entries",
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Taint),
                PolicyRecordContext::TaintSources,
            )
            .unwrap()
            .value_shape,
            PolicyValueShape::SourceEntries
        );
        assert!(
            lookup_applicable_field(
                PolicyRecord::EndpointSet,
                "include-matches",
                RqlpDocumentKind::Policy,
                Some(PolicyAnalysisKind::Taint),
                PolicyRecordContext::TaintSanitizers,
            )
            .is_none()
        );
    }

    #[test]
    fn atom_spellings_are_unique_within_their_domains() {
        for domain in [
            AtomDomain::AnalysisType,
            AtomDomain::GeneratedRelation,
            AtomDomain::Severity,
            AtomDomain::EndpointRole,
            AtomDomain::Port,
            AtomDomain::CallPort,
            AtomDomain::TaintMode,
            AtomDomain::TrustBoundary,
            AtomDomain::SystemEntry,
            AtomDomain::DirectoryScope,
            AtomDomain::TransferEffect,
            AtomDomain::Uncertainty,
            AtomDomain::ObservationPhase,
            AtomDomain::ExitScope,
            AtomDomain::CvssVersion,
            AtomDomain::CvssEmit,
            AtomDomain::CvssBasis,
            AtomDomain::CvssScope,
            AtomDomain::EvidenceRef,
            AtomDomain::OccurrenceRole,
            AtomDomain::ExpectedOccurrence,
            AtomDomain::OccurrenceNamespace,
            AtomDomain::Boolean,
        ] {
            let mut spellings = HashSet::new();
            for value in atom_values(domain) {
                assert!(!value.description.is_empty());
                for spelling in value.spellings {
                    assert!(
                        spellings.insert(*spelling),
                        "duplicate {spelling} in {domain:?}"
                    );
                    assert_eq!(lookup_atom(domain, spelling), Some(value));
                }
            }
        }

        assert!(lookup_atom(AtomDomain::CallPort, "receiver").is_some());
        assert!(lookup_atom(AtomDomain::CallPort, "return-value").is_some());
        assert!(lookup_atom(AtomDomain::CallPort, "matched-value").is_none());
        assert_eq!(
            PolicyValueShape::TypestateCallBinding.atom_domain(),
            Some(AtomDomain::CallPort)
        );
        let selector = lookup_atom(AtomDomain::EvidenceRef, "selector:/analysis/selector")
            .expect("selector evidence references are registry-defined");
        assert_eq!(selector.value, PolicyAtomValue::EvidenceSelector);
        assert_eq!(
            selector.matched_suffix("selector:/analysis/selector"),
            Some("/analysis/selector")
        );
        assert_eq!(
            PolicyValueShape::EvidenceReferences.atom_domain(),
            Some(AtomDomain::EvidenceRef)
        );
        assert_eq!(
            PolicyValueShape::EvidenceReferences.accepted_records(),
            &[PolicyRecord::EndpointRef]
        );
        assert!(
            PolicyValueShape::FixedOrUnratedSeverity
                .accepted_records()
                .is_empty()
        );
    }

    /// The assertion vocabulary must not become a private keyword list: every
    /// spelling an author can write for `:role` and `:namespace` is exactly one
    /// analyzer registry entry, and every registry entry is spellable.
    #[test]
    fn assertion_atom_spellings_mirror_the_analyzer_occurrence_registries() {
        use brokk_bifrost_rql::structural::occurrences::{
            ALL_NAMESPACES, ALL_OCCURRENCE_CLASSES, ALL_OCCURRENCE_ROLES,
        };

        let roles = atom_values(AtomDomain::OccurrenceRole)
            .flat_map(|descriptor| descriptor.spellings.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            roles,
            ALL_OCCURRENCE_ROLES
                .iter()
                .map(|role| role.label())
                .collect::<Vec<_>>()
        );

        let namespaces = atom_values(AtomDomain::OccurrenceNamespace)
            .flat_map(|descriptor| descriptor.spellings.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            namespaces,
            ALL_NAMESPACES
                .iter()
                .map(|namespace| namespace.label())
                .collect::<Vec<_>>()
        );

        // `:expect` is the class partition plus the explicit forbid spelling.
        let expected = atom_values(AtomDomain::ExpectedOccurrence)
            .flat_map(|descriptor| descriptor.spellings.iter().copied())
            .collect::<Vec<_>>();
        let mut classes = ALL_OCCURRENCE_CLASSES
            .iter()
            .map(|class| class.label())
            .filter(|label| *label != "non_reference")
            .collect::<Vec<_>>();
        classes.push("none");
        assert_eq!(expected, classes);
    }

    #[test]
    fn registry_collection_order_matches_canonical_normalization() {
        for field in [
            PolicyField::ExternalModelTransfers,
            PolicyField::PredicateAllValues,
            PolicyField::PredicateAnyValues,
            PolicyField::CvssPredicateAllValues,
            PolicyField::CvssPredicateAnyValues,
        ] {
            let descriptor = ALL_POLICY_FIELDS
                .iter()
                .find(|descriptor| descriptor.field == field)
                .unwrap();
            assert!(matches!(
                descriptor.multiplicity,
                ValueMultiplicity::Vector {
                    order: CollectionOrder::Set,
                    ..
                }
            ));
        }

        for field in [
            PolicyField::ClassificationRefinements,
            PolicyField::CvssMetricRules,
        ] {
            let descriptor = ALL_POLICY_FIELDS
                .iter()
                .find(|descriptor| descriptor.field == field)
                .unwrap();
            assert!(matches!(
                descriptor.multiplicity,
                ValueMultiplicity::Vector {
                    order: CollectionOrder::SourceOrder,
                    ..
                }
            ));
        }
    }

    #[test]
    fn cvss_base_metric_table_is_complete_and_rejects_x() {
        assert_eq!(ALL_CVSS_BASE_METRICS.len(), 11);
        let names = ALL_CVSS_BASE_METRICS
            .iter()
            .map(|descriptor| descriptor.spelling)
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), 11);
        for metric in ALL_CVSS_BASE_METRICS {
            assert!(!metric.legal_values.is_empty());
            assert!(!metric.legal_values.contains(&CvssMetricValueToken::X));
            assert_eq!(lookup_cvss_base_metric(metric.spelling), Some(metric));
        }
    }
}
