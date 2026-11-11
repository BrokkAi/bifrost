//! Evaluation units: the smallest piece of policy work a run reuses.
//!
//! A unit is one policy evaluated over one partition of the workspace -- for
//! the match family, one seed file -- together with the exact set of inputs
//! that execution read. Runs over two workspaces may share a unit's product when
//! every one of those reads still denotes the same content, which is what
//! [`verify_read_set`] decides.
//!
//! Nothing here is per policy or per family beyond the key's own fields. The
//! same key, the same verification and the same store serve every policy: a
//! family differs only in how its execution is partitioned, which is a
//! property of the plan's structure that the RQL crate computes.
//!
//! [`verify_read_set`]: brokk_bifrost_analysis::analyzer::verify_read_set

use brokk_bifrost_analysis::gitblob::ParseVariant;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use brokk_bifrost_analysis::analyzer::invalidation::{ArtifactVerdictLog, BudgetMode};
use brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest;
use brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetReplay;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::policy_units::{
    PolicyUnitAttestation, PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
};
use brokk_bifrost_analysis::analyzer::{
    ChangedFacts, HeadInputs, Language, Oid, ReadKey, ReadSetDigest, WorkspaceAnalyzer,
    analysis_epoch_digest,
};
use brokk_bifrost_flow::dataflow::SolverWork;
use brokk_bifrost_rql::PlanWidenDetail;
use brokk_bifrost_rql::structural::UnitExecutionResult;
use brokk_bifrost_rql::structural::identifier_typos::IdentifierTypoTable;
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnostic, CodeQueryExecutionWork,
};
use std::sync::Arc;

use super::budget::PolicyBudget;
use super::definition::{PolicyAnalysisType, PolicyId};
use super::finding::{PolicyFinding, PolicyFindingSeed, PolicyIncompleteReason};
use super::identity::PolicySemanticHash;
use super::projection::{TypestateProjectedFinding, TypestateProjectedFindingSeed};
use super::resolved::LoadedPolicy;
use super::typestate_policy::TypestateGap;

/// The digest a unit key carries when no semantic models were active.
///
/// A fixed value rather than an absent field: "no models were active" is an
/// input like any other, and a unit produced without models must not match one
/// produced with them.
const NO_ACTIVE_MODELS: &str = "bifrost-policy-unit:no-active-models:v1";

/// This crate's own revision, folded into the engine epoch beside the
/// analyzer's parser epochs.
///
/// The analyzer epoch says which parsers derived the facts a unit read. It
/// says nothing about how this crate shapes a published product or composes a
/// finding identity, and a run must read back neither from an older engine.
/// Bump this whenever a change makes either something this engine would no
/// longer mint.
///
/// #5495 replaces the fixed conditional-arm cutoff with shared bounded work.
/// Previously cached open coverage and missing long-chain findings must be
/// recomputed even when the source and language adapter epochs are unchanged.
///
/// The current value also carries #4321: complete external iterator protocol
/// evidence can now report a non-iterator at the returning method. Cached open
/// rows from the preceding engine must be recomputed.
///
/// The preceding value carried #3387: a Rust call nested below `std`, `core`, or
/// `alloc` keeps its extern-prelude identity when no activated model declares
/// its owner/member surface, records an extraction gap for it, or summarizes
/// it. When a model speaks to that path, its declaration gate decides whether
/// the callable identity is proven. Cached findings and open-coverage results
/// from the preceding engine can therefore disagree and must be recomputed.
///
/// The preceding value carried #3757: a Rust procedure whose implicit drops run
/// no user code, whose method calls resolve completely, or whose std calls the
/// reviewed std table models now concludes where the preceding engine left it
/// open, and a finding of a derived-complete run is definite where the
/// preceding engine reported it possible. A cached taint row from the
/// preceding engine still carries the open coverage and the possible
/// certainty, so it must be recomputed rather than replayed.
///
/// The preceding value carried #3513: a declaration row is identified by its
/// code unit and covered range, and the optional structural leaf kind is
/// presentation evidence the executor merges into the surviving row instead of
/// part of the key. A cached row from the preceding engine spells one
/// declaration's key once per kind its projections proved, so a union of the
/// member and the enclosing-declaration projections replayed from such a
/// product still publishes that one declaration once per spelling, and their
/// intersection still publishes no row for the declaration both name. Those
/// products must be recomputed rather than replayed.
///
/// The preceding value invalidated work receipts from before #3531's shared
/// runtime-syntax census and finding-first cold-root solve. Replaying old
/// per-procedure file or eager witness charges could retain an obsolete
/// budget boundary instead of running the corrected scan.
///
/// The one before that added #3205's row-level coverage envelope to persisted
/// query unit products: an analysis row now carries what its solver proved
/// about the partition it came from. A cached row from the engine before it
/// carries no coverage, which a reader would take as adding no restriction, so
/// a negative assertion over a reused flow, taint, typestate or type-flow
/// relation must be recomputed rather than replayed.
/// The preceding value added #3207's retained effect derivations to assertion
/// findings, including required truncation fields. Older assertion products
/// must be recomputed before the new reader decodes them.
/// The preceding value added #3151's row-level evidence object to persisted query
/// unit products. Cached rows from the preceding engine cannot satisfy exact
/// agreement with live query transports and must be recomputed. The previous
/// value added #2724's Rust call conversion producer. Cached rows
/// from the preceding engine reported unsupported-language evidence for these
/// same sources and must be recomputed to retain the newly established facts.
/// The preceding #2724 repair made cached rows retain field-scoped
/// unknown evidence. Older rows silently represented unknown conversions as
/// absent optional values, so their negative assertions must not be reused.
/// The previous value was #3054, which addressed the one byte anchor a typestate
/// canonical locator still carries -- its own -- from the start of the
/// innermost declaration it names instead of from the start of the file. A
/// typestate finding's subject identity is a digest of that rendering, and the
/// compiled binding-plan hash a root unit key carries folds it as well, so a
/// recorded base evaluation carries typestate finding identities this engine no
/// longer mints and a published root unit carries a key this engine no longer
/// computes. The first is the one a reader could not see: nothing detects it,
/// the recorded identities simply never join the head's, so every unchanged
/// violation reports as `fixed` and `new` forever -- against exactly the bases
/// this change exists to fix. The previous value was #3022, which took the byte
/// anchors out of the locator's declaration segments; the one before that was
/// #2968, which took the binding-plan hash out of the finding identity itself.
// #3868 preserves cross-domain witness labels and dependency mitigation proof
// in cached terminals. Older projected units lack this evidence and must miss.
// #5245: Cached no-sink results must not hide independently validated endpoint rows.
// #5297: Incomplete evaluation baselines can retain indexed custom-rule omissions.
// Their keys do not include the structural index representation version, so
// invalidate them to recompute with normalized node counts instead of work counts.
// #5294: Recompute products with source-attributed, relation-scoped diagnostics.
// #5338: Recompute percent-format facts with proven builtin operand shapes.
// #5310: Retain set projections and filter union representatives after merging.
// #5246: Recompute proven receiver closures with retained endpoint dependencies.
// #4811: Recompute products with diagnostics from every Python rule-fact producer.
// #5339: Recompute value-origin joins that omitted assignment binder roles.
// Old read sets cannot verify a lookup that the old evaluator never performed.
// #5339: Stores with binder-role joins can suppress Rust findings by resolving
// an inactive declaration token to an outer binding. Recompute those products.
// #5339: Recompute initializer proofs relative to each read, including earlier
// assignments in the same branch suite.
// #5385: Diff-base evaluations also cache unqualified loop diagnostics. Recompute
// their typed read causes and affected-procedure source locations.
// #5227: Recompute ICFG barrier policies previously cached as unsupported.
// #5506: Recompute explicit tuple-return shapes and starred-arity refusals.
// #5510: Recompute hierarchy diagnostics with root-class locations and actual reasons.
// #5495: Recompute branch relations with bounded work instead of an arm cap.
// #5498: Permitted ordinary special-method raises no longer inherit unrelated
// handler uncertainty. Recompute cached partial-discovery products.
// #5496: Rust branch distinctions now consume exact definition lookup evidence.
// #5534: Tuple-only absence and membership proofs replace cached open facts.
// #5511/#5721/#5745: Recompute ancestry, import and module-mutation proofs, including no-model inputs.
// #5738: Intrinsic-root fallback retains unadmitted claims under unchanged inputs.
// #5751: Module class-object aliases transport runtime ancestry at their RHS sites.
// #5532: Nested-header yields change generator invocation and return facts.
// #5598: Recompute module-body flow and enclosing-procedure ownership.
// #5812: Recompute value origins with classified iteration establishment sites.
// #5113: Inventory references preserve ownership holes in persisted selector rows.
// #5920: Persisted products carry the performed-source lane, separate from
// resident source holds that re-enter a later region's ledger.
// #5964: Recompute chain-demand completeness, including formerly false complete
// Boolean/wildcard products and operator-disjoint negative proofs.
// #7186: Recompute compact-constructor bindings; old read ledgers omit lexical lookups.
// #7289: a field initializer's right-hand reads are usages again. Query-time
// classification; policy read ledgers do not record it (#7262), so units from an
// older engine would replay the old answer.
// #7150: Go nested call result counts change call-binding answers.
// #7179: Recompute member-family rows that dropped established edges or
// carried no row coverage, and dispatch products that omitted their targets.
// #2445 Milestone 2: class-set roots now solve under an engine-owned
// allotment from a fresh ledger (#7294), which can complete a root that
// exhausted the asking policy's budget, so a unit persisted before it can hold
// a less complete answer than a fresh evaluation.
// #4365 M4: Recompute Java Javadoc rule findings, which now anchor on the
// offending @param or @throws tag instead of the whole declaration.
// #7379: Go nilness selects loads and stores through a pointer as dereferences.
// #7344, #7345: C# compound-assignment result writes join as overwrite candidates.
// #5658: Python single-writer identity and loop-local read openness change
// query-time answers that policy read ledgers do not record (#7262).
// #5658: deferred Python module reads count only structural module receivers.
// #7373: Recompute lexical bindings for contextual keyword identifier wrappers.
// #5658: Python attribute-space reads count only structural owners' writes.
// #5658: Python calls bind without demanding their arguments.
// #7371/#7372: exact nonlocal distinctions and initializer-independent bodies.
// #7179: unread Java ancestors and per-direction member-family completeness.
// #7547: String-literal predicates now consume decoded Java values.
// #4365 M3: Recompute statement-fact products. Java now produces rows, and C#
// and JavaScript statement-fact queries are incomplete instead of complete-empty.
// #7202: only explicitly classified summary returns establish receiver identity.
// #7107: Recompute units and base rows under content-diagnostic admission,
// per-item reporting, completion-code composition and exact diagnostic dedup.
// #7220: Query-time usage accounting changes for unchanged bytes; read ledgers record no usage lookup.
// #7226: Deref receiver steps change selected callees for unchanged source bytes.
// #7464: Recompute C# incoming-call products with exact overload target proof.
// #7368/#7369: Recompute C# cast and pattern argument binding identities.
// #7340: Recompute overwrite proofs whose gaps lie outside the selected live region.
// #7514: a sole global or nonlocal writer in another execution fixes Python identity.
// #7548: Configuration facts exclude generated .bifrost metadata directories.
// #7642: witness retention no longer removes findings; missing attribution is incomplete.
// #7620: invalidate units whose Java wildcard call applicability changed.
// Quicksilver round 12 on brokk-bifrost-analysis: Rust semicolon statements,
// Kotlin anonymous functions and labeled returns, and Scala declared types
// change Boolean result contexts; tokenless import binders take their import's
// span and source order. Both are query-time answers that policies read.
// Quicksilver round 12 tranche 2 on brokk-bifrost-analysis: Ruby closure
// capture reads, nested-loop counter sets and condition operators, and callable
// metrics that own only their root body change query-time facts policies read.
// #7578: Java native trial carrier proofs change policy admission; production stays gated.
// #7578: requirement origins select CFG-reaching writers, including loop backedges.
// #7471: Query-time Go binding selection changes policy results for unchanged bytes.
// #7619: inherited external JVM calls change policy binding answers.
// #7386: C# conditional-compilation regions make block, handler and useless-if
// emptiness undecided instead of certain, for unchanged bytes.
// #7341, #7342: Go constant-divisor and comma-ok map reads lower without fabricated panic gaps.
// #7617: unnamed Go composites publish direct type shapes.
// #7343: Recompute Go failure branches using the compared value's proven static type.
// #7393: Separate native handler identity from the structural body verdict.
// #7470: Type-switch and variadic static bindings change failure-handler results.
// Quicksilver round 12 tranche 3 on brokk-bifrost-analysis: XML attribute values
// get XML 1.0 normalization and YAML block scalars keep their chomped content,
// which configuration value predicates read.
// #7578: Branch-conditioned sanitizers kill taint on their guarded condition edges.
// #7618: Java native receiver-site classification changes call binding.
// #7560: C# models compose from catalog rows; composition reads one language's packs; CLR special member names split at the right dot.
// #7348/#7349/#7369: Java compound/static writes and pattern binding identities.
// #4379 M3b: C# statement rows and per-kind admission preserve unsupported enum coverage.
// #5658: Python member targets answer from the native definition under the trial.
// #5658: unimportable files stage their own references; unknown placement stays a reverse obligation.
// #7516: Go constructor shadows no longer seed package receivers, which changes reverse answers.
// #7673: Python module members follow the target module's re-exports under the trial.
// #7735: binding targets selecting their authored declaration are declaration sites.
// #5658: proven import declarations classify alias targets and synthetic import reads.
// #6234: bare Kotlin values bind receiver members before top-level properties.
// #7509 M3a: Go type answers at declaration names come from the declaration value slot.
// #3494: closed Ruby member selections discharge their dispatch gaps.
// #7509 M3a part 2: Go failure-handler binding proofs come from native evidence.
// Quicksilver round 13: Go non-return discovery admits receiver-as-argument method expressions.
// #7350: a resolved static or constant right-hand side is decided not a self-assignment.
// Quicksilver round 13: reusable summary and curated-model byte accounting charges owned payloads.
// Quicksilver round 13: typestate byte accounting moves registration and summary cap boundaries.
// #7918: Go field selections derive addressability from their receiver.
// #7536: initialization proofs discharge audited retained topology and evaluation-order gaps.
// #7915: value-flow plans no longer refuse a slot held both plain and substituted.
// #7508: C# conditional-expression branches model unproven conversions on both arms.
// #2445 M4b: deterministic property-reaching gaps no longer make units unbounded.
// Quicksilver round 13: type-flow summary store errors keep their kind in query diagnostics.
// Quicksilver round 13: composed taint certainty needs one proven-and-complete path; witnesses keep exceptional exits.
// Quicksilver round 13: canonical call-transfer sets compare callback provenance, so duplicates collapse.
// #7972: same-package cross-file static declarations close local self-assignment proofs.
// #7509 PR B: recompute Go model-authority member and receiver answers.
// #7509: source contexts resolve module-less relative Go imports.
// #7351: Go failure handlers prove error implementers and complete non-implementers by method set.
// #8036: native Go declared external receivers retain canonical callee identity.
// #7968: open Go member searches no longer decide interface mismatches.
// #8108: Java import inventory publishes fills with only stable incompleteness,
// so units previously unbounded by its refused fills now publish.
// #7509 G1b-1: Go owners behind incomplete imports lose the legacy G1b completion reason.
// #8097: assignment-relation flow gaps scope their withheld rows to the procedure's file.
// #3800: Python module-global reads are static loads, and fields on static loads are property subjects.
// #7362: query obligations ride beside binding certainty and reach unit diagnostics.
// #7505: member-family and candidate member ids carry canonical overload discriminators; family-derived finding ids rotate once.
// #7187: JVM lexical type formals and static-context barriers change binding queries.
// #4379 M6: C# cs/static-array follows CodeQL's definition test.
// #8146: boolean patterns evaluate role targets that have no normalized kind.
// #4379: C# nested-if and misleading-indentation query-local statement facts.
// #2445: typed diagnostic causes admit content-only partial evaluation units.
// #8148: authority inputs key binary file bytes without source decoding.
// #6664: failed descendant reads are incomplete, not cancelled or empty.
// #4379: C# rethrows publish throw anchors and unwrap parenthesized operands.
// #8153: overloads of one owner do not prove a call target.
// #8000: on-demand JVM imports bind provider-indexed external types.
// Quicksilver round 13: RQL conditional-wrapper answers key on remaining depth, and ambiguous modeled
// Rust owners propagate, so both fixed points no longer depend on visit order.
// #7509 G1b-2: modeled Go callable results are typed natively, without the legacy reason.
// #7391: Go type assertion results change receiver binding and usage answers.
// #7153: C++ guarded field definition answers change policy inputs.
// #6945: curated Python star children change module and call bindings.
// #8154: recursive empty-arm answers depend on uncertain statements and omissions.
// #7424: old Java enum-switch units can claim a clean negative without reading the enum file.
// #7577: Scala cast expression types change call applicability and bindings.
// #8126 retains snapshot-stable memo fill failures and replays their evidence.
// #7761 / #8184: retained fills own request-cache domains and capture only their own gaps.
// #8242: taint endpoint supersedes edges reduce same-point, same-phase, same-carrier
// endpoints before events are minted.
// Quicksilver round 13: same-project configuration joins match file-valued code rows, and a selected-property
// budget, cancellation or provider cut marks its unit instead of being admitted as content.
// #7240: imported constructor receiver proofs change usage and reverse answers.
// #2445: an unsupported external member family is an open hierarchy_unenumerated boundary, not truncated.
// Quicksilver round 13: only the global CException is the MFC root, C++ bases resolve through the shared
// resolver, printf literals keep their width and floating kind, XML attributes compare as a set, and Rust
// marker bindings follow block and module scope.
// #8262: missing model hierarchy endpoints withhold authoritative absence.
// #8264: predeclared Go modeled result types change receiver, value and binding answers.
// #7509 G1b-3 B: Go result-contract field classification for promoted fields stays open.
// #8147 M4a applies preprocessor decisions to C# syntax and resolution facts.
// #8290: a repeated read through one forward operation keeps the closed root's closure discharges, so warm answers change.
// #2445: stable Python result-obligation, return-profile and hierarchy gaps are content, not provider stops.
// #7314 C1-4b: the C# native demand trial answers definitions and names external misses.
// Quicksilver round 13: Python rule facts recognize __ne__ delegation, receiver stores, explicit super
// classes, loop kinds and main guards correctly; builtin format, copy.deepcopy, mutable-default
// emptiness, qualified bases and range aliases follow Python semantics; a receiver-read gap is a reason.
// #7509 G1b-3 B follow-up: Go pointer-field proofs no longer require a public pointee owner.
// #8167: native Java call bindings explain calls with no selected executable from the reached model family.
// #8222: Scala's external-type ladder follows Scala's binding order and implicit roots.
// #8300: a resolved-value candidate proven to be another identity no longer makes discovery incomplete.
// #8305: a call port on a field-write sink refuses binding instead of binding the right-hand call.
// #8201: fixed-cap and malformed external index reads are stable, so their fills are retained
// #7314 C1-4d1: qualified C# type routes change trial resolution answers.
// #7314 C1-4d2: C# using aliases change trial resolution answers.
// #7314 C1-4d3: namespace and static using tiers retain external and compilation obligations.
// #8403: an unrelated same-named call of a different arity no longer leaves a Rust reverse inventory incomplete.
// #7314 C1-5a1: a new overlay-only C# file gets proven compilation placements.
// qs13 policy P1: winning-tier assertions keep sites with no candidate rows, duplicate checks compare decoded values, and classification keys are (taxonomy, identifier) pairs, so which policies load and what they report change.
// #8333: native Scala compiler roots bind to their closed intrinsic owners.
// #7027 S2b: native JVM ancestor ambiguity and open reasons change hierarchy consumers.
// #7314 C1-5a2: compilation-wide source aliases change trial C# answers.
// qs13 policy P4: relational coverage truncation is reported truthfully, store-crossing witnesses keep their own read seed, composition diagnostics are bounded instead of dropped, the Rust format identity needs a complete dispatch, and typestate helper closes discharge a formal only at close points where every fact is a proven close of that formal (conditional releases only when true), so policy results and their evidence change.
// #7314 C1-5b: authored global globs and structured compilation using routes
// #7027 S2c: hierarchy content diagnostics preserve partial edges and affect admission.
// #8411: static openness in effect coverage is content incompleteness, so those units become reusable.
// #8496: provider-free Scala aliases plan authored on-demand packages.
// #8279: Scala bindings follow SLS chapter 2 scope-aware precedence.
// #8287 sliced merges no longer widen on merged limits; truncation and budget
// exhaustion are reported as incompleteness.
// #7509 G1b-3 A: Go exact-binding result identity is native (alias, shape and nominal answers change).
// #7314 C1-5c: compilation-unit closure requires source and metadata coverage
// #8385: read-key digests exclude absolute source positions; rank carries order.
// qs13 policy P2: a replacement endpoint-set import whose resulting retained total fits the limit is admitted, and retained sizes count boxed-slice storage, so which policies load and what a run keeps change.
// #8845: per-framework Razor path evaluation changes project inventory admission.
// #7314 C1-4e AD1 (-7314-c1-4e-ad1-csharp-membership-unproven): admission retains named membership gaps.
// #7027 S3: native JVM descendant ambiguity, open frontiers and budget cuts affect hierarchy consumers.
// #8147 M4b parses each C# file under its owning projects' symbols, so decided chains keep their decided branch.
// #8147 M4c: answers that may depend on an unparsed undecided C# #if branch become incomplete.
// #8306: await results depend on the awaited value; C# async procedures lose their procedure-scope gap.
// #8309: C# resolved-value resolves typeof operands (and their AssemblyQualifiedName/FullName reads) instead of reporting them incomplete.
// #7366: a field-write finding whose member is a source declaration is reported instead of failing the run.
// #7027 S2b-0: implicit JVM supertypes close member lookups through kotlin.Any, kotlin.Annotation and Scala AnyRef.
// #8308: C# call points name their structural fact; string equality with a literal is a constant-equality guard.
// #8388: composition requires an explicit complete caller-inventory coverage instead of trusting Native authority.
// #8486: stable content diagnostics permit replayable JVM external-index reads.
// #8457: Rust trait-impl member inventories are open, so composed taint through them reports partial discovery.
// #8453: Go concrete method inventories are open; Go composition does not read them yet.
// #8513: report retention and evaluation share the workspace-scaled per-policy budget, clamped to the batch's retained-byte cap, so what a narrowed run keeps changes.
// #8546: model overrides apply only to their analyzer, so a nested diff base reads its own publication.
// #8402: Go publishes semantic IR at parse time; under a finite budget a stored artifact can complete where on-demand lowering exceeded it.
// #7314 C1-4e AD2: per-file membership and open declaration inventories.
// #7314: demand halves distinguish stopped work from open source rows.
// #7234: PHP static scopes reach the member their class effectively has (late static binding for `static::`), and PHP class and method names match without ASCII case.
// #8579: Java, Kotlin and C# publish semantic IR at parse time, with the same finite-budget difference.
// 53a7f9429a: an unsupported requested route relation blocks terminal route certificates (Rust Export #8152, C++ #8199)
// #7750: Java procedures with a guarded switch lower instead of failing the semantic IR switch contract.
// #8283: structural Go result proofs can make previously open result uses exhaustive.
// #7509 G1b-3 F (-7509-g1b3-f-nested-call-arity): Go nested-call result counts come from the native selected callable, so call-shape completion changes.
// #8632: parent-relative open placements and conservative escape obligations affect C# answers.
// #8602: observer-free exceptional exits change flow relations and overwrite proofs.
// #8586: every artifact is lowered under one producer budget and admitted by its census, so a unit's completion no longer depends on whether the artifact came from rows, the cache, or lowering.
// #8665: Scala import bridges retain the transitive import chain's open-boundary reasons.
// #7027 S2b-0: implicit JVM roots and closed root member inventories change answers.
// #8516: package member providers change selected policy bindings.
// #7314: C# method answers stay open until applicability is modeled.
// #8705: a Scala implicit root's own positive binding no longer discharges its open gap, so those answers stay incomplete.
// #8667 (-8667-go-nested-arity-gap): Go nested-call result counts that are unknown for a deterministic reason now carry a SemanticEvidenceGap, so call-shape completion changes.
// #7509 G1b-3 G (-7509-g1b3-g-untyped-receiver-native-count): a nested Go selector call whose receiver the source inference cannot type takes its result count from the native selected callable, so call-shape answers can become more complete.
// #7960: a JavaScript call's thrown value binds the catch parameter that handles it, so taint can reach a catch body.
// #8790 (-8790-go-path-index-stable-gap-replay): Go's workspace path index and import facts replay a stable structural gap instead of refusing, so policy units that read them can now be published.
// #7800: structural match rows carry the heuristic reason of the language relation that selected them, which makes their findings possible.
// #8025: JS/TS namespace import reads are static loads, so fields on them are property subjects.
// #8836 (-8836-revert-js-call-throw-catch-binding): revert #7960; a JavaScript call's thrown value no longer binds the catch parameter, so catch-body field reads through the binder decide again.
// #8831: C# target property assignments change compilation membership and symbol decisions.
// #8896: returned-member ports and boundary coverage change composed taint answers.
// #7509 3a (-7509-3a-native-call-application-roles): Go call application roles come from selected native evidence, so a method expression on a parenthesized type operand is Unknown instead of a guessed bound receiver.
// #8872: Recompute receiver evidence that discarded a proven JS/TS package module.
// #7509 5b step 1 (-7509-m5b1-native-selector-refinement): Go source selector refinement uses selected native member evidence (preparation, field anchor, interface trigger) instead of the legacy typed selector target.
// #8856: Diff-base replay records actual grants and certified census outside its budget-independent key.
// #8388: an unproven Go builtin assumption keeps an ICFG snapshot open, so it is never refined into Complete.
// #8389: typed unit keys separate root locator and compilation.
// #8823 (-8823-jdk-pack-type-parameter-scope): the generated JDK pack keeps an inner class's enclosing type-parameter scope through the source/binary merge, so the JDK 21 pack validates and JDK calls rebind to its models.
// #7509 5b step 2 (-7509-m5b2-native-allocation-refinement): Go allocation dispatch narrowing uses the selected allocation type and one complete native member instead of the legacy source inference, so a failed selection keeps broad dispatch.
// #8870 (-8870-composed-entry-points): composed policies bind declared entry formals as origins.
// #7509 (-7509-function-field-call-application): a function-valued Go field call has no bound receiver.
// #8866: Rust receivers through std unwraps bind modeled methods.
// #8884 (-8884-rust-selected-import-reads): Rust external proofs read imports from the selected operation.
// #8822 (-8822-csharp-inventory-closed-derivations): a resolved C# definition lookup stays Resolved under an open package inventory when its derivation is proven closed under additions, so call targets and branch comparisons can complete.
// #7509 5b step 3 (-7509-m5b3-native-nested-call-result-counts): Go nested-call result counts come from the selected native definition signature instead of the legacy source inference.
// #7869 (-7869-package-boundary-per-alternative): an unacquired JVM package provider is a per-reference obligation, and a targetless answer stays open.
// #8898 (-8898-cancelled-procedure-openness): a cancelled procedure openness request reports Cancelled instead of Complete; policy units built while that could happen are recomputed.
// #7509 5b step 3 (-7509-retire-go-expression-inference): the legacy Go callee expression inference no longer backs function-value result obligations, so its reads and the false positives it could produce are retired.
// #8803 (-8803-csharp-enclosing-namespace-scope): C# enclosing namespace scope selection changes query-time bindings.
// #8870: composed store ends link remote writes to read origins.
// #8870 (-8870-store-ended-candidates): composed candidate answers include store crossings.
// #8870 (-8870-composed-conditional-sanitizers): composed taint applies policy-bound conditional edge kills by label group, changing policy answers.
// #7619: parameterized JDK call results bind type-parameter-free receiver members.
// #8487 (-8487-java-on-demand-package-outcomes): Java on-demand package reads now attach typed outcomes to the selected reference frame.
// #8992 (-8992-jvm-on-demand-declaration-admission): JVM glob admission requires provider-declared existence before shadowing defaults.
// #8389 (-8389-charge-reused-units): a reused policy unit debits this run's remaining allowance before later units execute.
// #8389 (-8389-union-seed-local-suffix): union suffix admission changes unit slicing.
// #7509 G2 (-7509-go-structural-signature-identity): Go interface satisfaction proves slice, map and predeclared error signature identity instead of leaving every structural slot Inconclusive, and shared projected type shapes fold every node's completion.
// #7509 5b step 4 (-7509-m5b4b-native-function-value-proof): Go named function-value error obligations come from the selected declared type and its nominal declaration instead of the legacy type-name resolution, and a bounded stop in that proof is reported as operational incompleteness.
// #8996 (-8996-diff-base-reliability): explicit NotRun head policies no longer condemn stored diff bases.
// #7509 5b step 4 (-7509-m5b4a-selected-aggregate-owner): Go external field memory takes its aggregate owner from the selected native type through the shared nominal-owner admission, which also changes the declared-type proof behind function-value obligations.
// #8963 (-8963-go-result-obligation-coverage): a Go call-result obligation row whose dispatch arms have an unknown signature and no derived obligation reports Open coverage, so the query records ResultObligationDerivationIncomplete instead of Complete.
// #8870 (-8870-composed-flow-policies): complete flow endpoint inventory changes read receipts.
// #8991 (-8991-rust-let-copy-allocation): a Rust by-value let of a struct owns its storage, which changes retained taint evaluations.
// #2508: native Rust/Go effect results compose the stored invocation IR.
// #8978 (-8978-rust-branch-value-join): Rust if, match and block values join their branch tails, which changes retained taint evaluations.
// #7804 (-7804-java-fqn-expression-prefix): Java expression prefixes root package and type routes, and targetless answers need language-owned terminal proof to close.
// #8389: intersect-prefix reuse changes the persisted product and policy slicing route.
// #8896 (-8896-composed-member-call-bindings): composition binds callee heap writes back to shared caller storage.
// #8389 (-8389-typestate-root-fit): a reused typestate root must fit every lane, including retained lease bytes, so evaluations retained under the old reuse charge are not replayed.
// #8389 (-8389-native-output-units): composed outputs are reusable by stable reported site.
// #9013 (-9013-rust-call-guard-truthy): a Rust call used as a condition is a Truthy guard and Rust barrier carriers are typed, which changes conditional-sanitizer answers.
// #7314 M1f slice 6a (-7314-m1f-java-common-import-context): Java selected contexts use the shared JVM import assembly.
// #9063 (-9063-go-certified-method-collision): a certified same-depth Go promotion collision is absent from the method set, so the type no longer satisfies the interface and retained policy units change.
// #9084 (-9084-declaration-finding-anchors): a finding that selects a whole declaration is anchored on the declaration's identity instead of its source slice and span, so stored evaluations carry different finding ids.
// #8741: implicit root edges are independent of publication order.
// #8834: selected JVM root presence reads now invalidate reused policy units.
// #8811 (-8675-pre-closed-relation-discharge-replay): closed relation discharges now reach newly built requests before their answers are retained.
// #8386 (-8386-value-flow-neutral-endpoint-ids): public reached value-flow IDs use the plan and full event identities; Rust endpoint-only queries route through the shared composition client, retained_witnesses counts describe only requested witness steps, and endpoint evidence aggregates alternative derivations.
// #9127 (-9127-mount-free-value-flow-plan-identity): the public value-flow plan fingerprint inside reached endpoint IDs no longer hashes the workspace mount, so stored value-flow IDs change.
// #8896 (-8896-returned-member-ports): returned member ports and composition binding change retained policy answers.
// #8940 (-8940-post-call-heap-ports): post-call shared storage ports change retained policy answers.
// #8896 (-8896-icfg-member-call-bindings): ICFG call plans transport copied member contents.
// #9162 (-9162-partial-flow-seed-canonicalization): every builtin partial-flow seed of one port shares one seed key, so stored partial-flow rows, and the composed and retained policy answers that read them, change.
// #8962 (-8962-semantic-artifact-window-admission): CallEffects runs in per-file artifact windows, and inside a window every admitted artifact's own row charge is grant-neutral (retained bytes stay capped), so budget-incomplete results can now complete.
// #8893 (-8893-rust-selected-operation-reuse): nested Rust receiver, modeled-member, trait-applicability and imported-callee proofs under a selected operation reuse that operation instead of opening fresh ones, so their reads come from the caller's pinned selection and the query does far less resolution work.
// #9196 (-9196-closure-invocation-certificates): invocation, root and capture
// admission plus Rust local-closure dispatch proof change retained policy answers.
// #9230 (-9230-rql-native-caller-inventory): RQL call relations treat a native incoming answer whose caller inventory is not Complete as incomplete, so retained match, selector and policy unit answers that were Complete change.
// #9060 (-9060-typed-round-ready-queue): typed-round call-result forwarding can complete roots whose retained policy units previously stopped at the budget.
// #9195 (-9195-native-scala-alias-parents): native Scala follows selected source alias parents, changing member-family ancestry, descendants, virtual dispatch, and retained policy answers.
// #9220 (-9220-jvm-renamed-member-imports): renamed Scala and Kotlin object-member imports select the authored member, changing retained policy answers.
// #6291 (-6291-native-java-call-binding-corrections): native Java's explicit-import boundaries, unread Object ancestor and constructor identity change call-binding and dispatch answers retained by policy units.
// #6792 (-6792-scala-bare-term-bindings): bare Scala method values and
// term-family bindings change retained member and call policy answers.
// #8389 (-8389-file-local-set-minuend): an except over a file-local union minuend runs per seed and merges in seed order where it ran whole before, so retained, verification and whole or zero-result evaluation keys change even when complete row sets agree.
// #8388 (-8388-go-composed-taint): Go admission and shared writeback and partial-flow corrections change composition and ICFG-backed value-flow answers.
// #7654 (-7654-scala-anyref-object-members): selected Object member dispatch
// and call answers reach retained policy units through the ICFG provider.
// #9097 (-9276-store-witness-source-sites): store crossings keep their source event, so ordinary witnesses can name a distinct write where two source events used to collapse, and flow candidates match a crossing to their own source site.
// #8389 (-8389-root-union-file-local-set): a root union of file-local set subtrees runs its authored tree per seed and merges in seed order where it ran whole before, so retained, verification and whole or zero-result evaluation keys change even when complete row sets agree.
// #8386 (-8386-go-composed-value-flow): ready Go value-flow plans select the composed search instead of ICFG, which changes RQL-backed retained policy units and whole or zero-result evaluations.
// #8870 (-8870-go-conditional-composition): Go policies with a conditional sanitizer select composition instead of ICFG, which changes findings, completion and diagnostics retained for them.
// #8826 (-8826-csharp-undecided-scan-receipt): selected-content C# publication now keeps its
// undecided-chain scan, so restored chains add SemanticEvidenceGap reasons to file and scope reads.
// #7509 (-7509-go-sole-alias-owner): selected Go alias definitions now reach
// point and receiver reads, changing retained policy unit answers.
// #9195 (-9195-scala-reference-package-contexts): exact Scala reference package
// contexts change selected hierarchy answers retained by policy units.
// #9323 (-9323-kotlin-jdk-static-calls): Kotlin static JDK calls and closed
// java.lang value names change retained policy unit answers.
// #8386 (-8386-composed-rowless-sink-artifacts): charged Complete sink artifacts in this compile admit composition without stored rows.
// #9270 (-9270-csharp-yield-normal-continuation): partial C# yield continuation changes policy answers; whole and zero-unit evaluation keys do not carry the adapter epoch.
// #7726 (-7726-kotlin-native-call-evidence): Kotlin JDK call proofs reach
// dispatch and call bindings, changing retained policy unit answers.
// #8826 (-8826-query-memo-admission): limited C# global-using calls no longer seed full cells, changing alias-dependent ICFG dispatch and retained policy answers.
// #8386 (-8386-typestate-composition): Rust lifecycle object composition and receiver-mode proofs change findings and retained evaluations.
// #9183 (-9183-typestate-alias-guards): guarded typestate summaries retain selected local-event templates and caller alias decisions, changing retained policy answers.
// #9277 (-9277-go-selected-context-reconciliation): scoped Go reconciles its selected source/configuration snapshot, changing native context availability and retained policy answers.
// #7960 (-7960-reland-js-call-throw-definition-alternatives): a JavaScript call's thrown value
// binds the catch parameter again, and a field read through a binder several copies define is
// resolved once per definition, so retained taint answers through try/catch change.
// #9378 (-9378-indexed-modeled-call-results): indexed modeled call results get their complete modeled identity, changing heap answers that retained policy units read.
// #9378 (-9378-composed-result-activation): composed typestate starts a result-contract seed only on its activation edge, which changes composed root, whole and zero-result evaluation products.
// #9323 (-9323-kotlin-jdk-constructor-callees): Kotlin constructor callees of
// imported JDK types bind their constructors, changing retained policy unit answers.
// #9378 (-9378-go-pointer-handoffs): Go pointer argument and receiver handoffs certify composed typestate continuity and change selected dispatch answers retained by policy units.
// #9412 (-9412-scala-local-package-precedence): a Scala member of a certified
// enclosing package again suppresses default-import gaps, which changes retained
// selected hierarchy answers.
// #7509: directional Go channel identity changes retained method and call answers.
// #9330 (-9330-php-element-concat-flow): PHP element reads, `.`, `.=` and `??` lower operand flows
// without procedure gaps, so retained PHP taint answers change.
// #9331 (-9331-php-string-interpolation-flow): PHP interpolated strings and heredocs flow every
// interpolated part into the string, so retained PHP taint answers change.
// #9203 (-9203-rust-owned-receiver-events): owned receiver events change retained units and whole/zero results.
// #9324 (-9324-scala-jdk-call-targets): Scala JDK calls and external constructor
// references gain proven targets, changing retained call-binding answers.
// #9438: decorator Arg roles change arity matches on existing valid decorator queries.
// #9438 follow-up: comment extras and parenthesized decorators change retained answers.
// #5658 (-5658-python-native-production-switch): Python product surfaces answer from the native engine, so Python policy units built from the legacy resolver are recomputed.
// #9431 (-9431-lifecycle-coverage-claims): selected procedure lifecycle claims change typestate uncertainty and retained policy answers.
// #9002 (-9002-jvm-lexical-head-blockers): a qualified JVM name whose head keeps an open lexical choice now carries that head's protected reason to its continuations, so retained policy answers that read those continuations change.
// #9060 (-9060-semi-naive-typed-rounds): semi-naive typed rounds can complete roots whose retained policy units previously stopped at the same budget.
// #8723: recorded C# branch obligations reach structural answer completion.
// #9432 (-9432-go-modeled-imported-formal-authority): modeled Fresh call-result origins certify imported formals (Go pointers and Java
// class formals) and rehome selected objects, changing composed typestate answers and retained root, whole and zero-result evaluations.
// #9522 (-9522-receiver-incomplete-candidates): possible receiver targets change open dispatch and coverage answers.
// #9486 (-9486-modeled-producer-origin): a modeled Fresh producer's exact origin certificate closes its own
// creation-boundary Object item, so composed typestate answers can become Complete.
// #9532 (-9532-java-external-formal-type-arguments): Java external call proofs over formals with unproven type arguments change retained call-binding answers.
// #7365: declaration attribute capability changes retained policy completeness.
// #8389 (-8389-set-prefix-reuse): root union and except over seed-local operands slice by seed prefix,
// changing the persisted Prefix product (operator tag) and the slicing route.
// #9561: negated and Boolean-composed features now withhold unsupported answers.
// #9447 (-9447-structured-formal-roles): formal-role publication/refusal and
// stable local Go function-literal target/capture proofs change retained call,
// binding, and policy unit answers.
// #9183 (-9183-typestate-alias-guards): callee footprint certificates, shared gap reconciliation, the F1 subject witness and F2 exclusion, conditional-presence alias guards, and mount-independent binding-plan identity change typestate answers and root reuse.
// Its same unpublished epoch also covers declared application-result obligations
// admitted through the shared exact source-call certificate.
// #9550/#9566: uncovered reusable summaries change typestate and policy answers.
// #9879: admitted Go scoped call/control coverage changes typestate completion.
// #8389 (-8389-typestate-set-union-slice): typestate union selectors retain merged structural rows before site projection.
// #9582: complete empty operand-zero probes avoid evaluating later set operands.
// #4379 M4b: C# declarations expose their modifiers and type kinds, changing retained answers.
// #9595: persisted prefix completion reasons omit redundant discovery failures.
// #9557 (-9557-native-java-unread-ancestors): native Java and Scala member families name certified unread ancestors and language roots, changing member-family answers and completeness.
// #8870 (-8870-java-static-import-reverse-completeness): the Java reverse producer marks a target
// Incomplete when a static on-demand import could expose its name without binder authority.
// #8870 (-8870-java-nested-reverse-owners): the Java reverse producer nominates structured
// enclosing-type spellings for nested targets and opens inherited nested routes it cannot certify.
// #8675 S2 (-8675-s2-java-type-frontier-authority): selected Java Type-frontier gap authority changes retained answers.
// #9658 (-9658-composed-terminal-provenance): subject-bound composed terminal admission changes retained root findings.
// #9614: attribute predicates under :and/:or/:not inherit the enclosing pattern's kind, so answers move from incomplete to complete.
// #8870: selected Java call frames certify caller identity for incoming inventories.
// #9612: filtered unclassified reference sites change retained policy completeness.
// #7857 (-7857-modeled-member-candidates): modelled candidates carry their pack provider, and Python's selected modelled members project into candidate traces (SelectionOnly), so retained candidate-derived policy answers change.
// #9546 M1a (-9546-m1a-selected-import-authority): the selected store decides Java simple type names, and N.member prefixes keep Incomplete answers instead of a selected import boundary.
// #9563 (-9563-semi-naive-query-node-obligations): semi-naive typed rounds keep the query obligations held by a clean reference's owned and read query nodes, so retained policy answers that read those obligations or the completion they affect change.
// #9002 (-9002-jvm-lexical-head-blockers): protected lexical head reasons reach qualified-name continuations.
// #9575: read-side mutation queries rescan rather than reuse stopped or unreceipted outcomes.
// Each operation now owns one coherent scan; unreceipted consumption refuses retained reuse.
// #9447 (-9447-structured-formal-roles): formal-role publication/refusal and
// stable local Go function-literal target/capture proofs change retained call,
// binding, and policy unit answers.
// Its same unpublished epoch also covers declared application-result obligations
// admitted through the shared exact source-call certificate.
// #9563 (-9563-semi-naive-query-node-obligations): semi-naive typed rounds keep the query obligations held by a clean reference's owned and read query nodes, so retained policy answers that read those obligations or the completion they affect change.
// #7040 (-7040-rust-gap-diagnostic-path): retained policy units carry Rust diagnostic evidence with workspace-relative paths.
// #5658 M8 (-5658-python-file-local-lowering): Python imports and callees lower from the file alone, so retained Python call and policy answers change.
// #8837 (-8837-csharp-configuration-presence): C# reads Directory.Build/Packages presence; a present 0-byte file opens membership and GetPathOfFileAbove passes proven-absent directories, changing retained answers; units recorded before native membership reads carried the configuration fact cannot be reused.
// #9779 (-9779-cpp-recovered-lexical-formals): C++ macro-recovery owners bind no lexical parameters, and proven recovered formals publish signatures.
// #9612 M2 (-9612-field-access-facets): C# and Java field reads and writes are decided from the access position, so retained edge rows and kind-filtered answers change.
// #9784 (-9784-stored-semantic-ir-read-admission): stored semantic IR publication reads are recorded as typed read keys and verified at replay, so units retained without that receipt must recompute.
// #8500 (-8500-certified-owner-targets-and-reverse-obligations): certified external-owner targets, per-owner obligation retirement and
// Unproven reverse edges while query obligations are outstanding.
// #9810 (-9810-go-field-access-facets): Go field access positions change retained edge rows and kind-filtered answers.
// #9840 (-9840-warm-activation-carry): warm updates carry verified dependency-discovery evidence instead of dropping it, so retained units built from the degraded evidence cannot be reused.
// #9651 (-9651-formal-member-overwrite): an exact store through an unrebound formal kills the member's earlier value, and C# slot stores drop the accessor gap.
// #9835: Rust selected call results use sparse formal ordinals for explicit generic arguments.
// #9868 (-9868-unknown-binder-source-refusal): Unknown matched-value binders refuse a clean empty source; only affirmative Complete-empty declaration evidence remains clean.
// #9863 (-9863-rust-first-unreachable-region): Rust statement-reachability rows expose the first visible unreachable node of a CFG region, changing retained query answers on unchanged source.
// #9773 (-9773-java-assignment-operator): Java assignment operators decide field reads in retained answers.
// #9746 (-9746-composition-root-publication): composition typestate roots are published and replayed as root products, and their memo answers replay the read receipts behind them, so retained typestate units built before composition roots were stored cannot be reused.
// #9687 (-9687-e1-rust-result-producers): Rust expressions produce their result values (assignments, loops, tuples, ranges, break values) and value joins move aggregates, so retained policy answers that read those procedures change.
// #9783 (-9783-selected-import-owner-publication): selected explicit-import owners change reference targets, definitions and completion.
// #9934 (-9934-rust-wildcard-assignment-discard): pure wildcard assignment evaluates its RHS without an Assignments gap, changing retained Rust procedure completeness and policy answers.
// #9852 (-9852-go-external-leaf-certification): an external Go signature leaf counts only when the current close attempt certifies its owner.
// #9971 (-9971-edge-match-candidates): edge rows retain source-anchored policy findings.
// #9324 (-9324-inapplicable-external-access-gaps): an external overload the call's arguments reject discharges its access gap, so retained JVM call answers change.
// #10014 (-10014-receiver-taint-rows): under incomplete discovery, exact receiver call bindings select receiver sinks, so retained taint answers change.
// #9971 (-9971-edge-provenance): adapted edge steps preserve complete finding provenance.
// #10045 (-10045-authored-family-precedence): certified authored Rust free-function families retain complete locators after std composition.
// #9918 (-9918-rust-local-import-routes): Rust unit summaries join retained import routes by binder, so relative local imports and glob cycles resolve and summaries that read them change.
// #9444: Rust pattern-name and closure capture uncertainty changes retained policy answers.
// #9937 (-9937-partial-summary-positive-transfers): selected partial-summary transfers change retained policy answers while the call remains open.
// #9546 (-9546-java-usage-evidence-receipt-replay): a Java usage-evidence cache hit now replays its producer's read receipt, so units retained from a hit that omitted those reads must recompute.
// #5658 M8 (-5658-python-with-suppression-candidate-edges): the Python `with` suppression route is an unproven control branch, so retained Python policy answers change.
// #9863 (-9863-localized-statement-reachability): certain and possible statement routes compose with candidate control edges.
// #10042 (-10042-rust-missing-target-roots): a Rust target root or workspace entry that discovery cannot place now leaves the crate inventory incomplete, so retained answers over such crates change.
// #9954: Go scoped call/control coverage now admits qualified callees and binary conditions.
// #9925: guarded Rust pattern projections and Poem selection change retained policy bindings.
// #9319 (-9319-ruby-gem-lock-activation): exact Gemfile.lock gems become Ruby activation evidence, so retained gem boundaries and package-scoped model selection change on unchanged source.
// #9794 (-9794-go-deferred-call-result-pointer): a Go deferred by-value capture of a pointer-typed local keeps referent identity at query time, so retained Go typestate answers change.
// #9479 (-9479-scala-parameterless-selection-calls): Scala parameterless member selections lower as call sites and RQL admits them as calls once resolution proves the member callable, so retained Scala call answers change.
// #9423 (-9423-jvm-external-supertype-targets): Kotlin and Scala JDK overload answers change once the JVM subtype walk reads extracted supertype targets.
// #10021 (-10021-creation-type-from-qualifier): a creation's type completion follows its type qualifier, so receivers of `new T(...)` and their call answers change.
// #10096 (-10096-composed-witness-seed): composed typestate witnesses retain the ICFG seed step, changing stored finding witnesses.
// #10050 (-10050-configuration-directory-field): policy units persist every row field, so old units have no directory join key and would falsely report a fixed Web.config.
// #9863 M1c (-9863-rust-feasible-literal-guards): Rust literal guards and bare wildcard patterns prune infeasible CFG successors in statement reachability and dead-write liveness.
// #10061 (-10061-go-method-call-result-pointer): a statically selected Go method's declared pointer result can preserve a deferred capture's referent identity.
// #9559 (-9559-request-owned-carried-anchors): a request-owned external pack record anchors only to a source the pack carries, never to a workspace declaration that shares its entry path and name, so retained answers that read authored-path lookups or anchored locations change.
// #7708 (-7708-declared-type-argument-transport): call arguments carry their declared type arguments and same-owner wildcard containment decides Java overloads, so retained call answers change.
// #10052: exact qualified lookup now finds dotted CLR and explicit member names.
// #10166 (-10166-inventory-excludes-analyzer-cache): workspace inventory no longer includes analyzer-owned cache files, changing retained policy answers that read it.
// #10161: exact Go typed-var call-result identity changes ordered typestate proof.
// #10168 (-10168-reaching-writer-at-capture): a captured Go local counts only writers reaching registration.
// #9737 (-9737-recorded-derivation-inputs): policy units verify recorded derivation identities across heads.
// #10088 (-10088-depth-bound-reached): unit and prefix products retain the call-depth status and its read receipt; declared completion changes retained policy answers.
// #9642 (-9642-protocol-coverage-admission): typestate protocol coverage is Complete only when both #9550 admissions pass, and exact-result retention covers the Protocol-admitted branch, so retained typestate answers and work fields change.
// #9766 (-9766-separated-join-members): separated value-copy alternatives retain return-member provenance, so retained policy answers change.
// #9324 (-9324-scala-reference-conversions): Scala call applicability refutes reference-typed overloads through the closed JVM hierarchy, so Scala JDK overload answers change.
// #10097 (-10097-role-name-inventory-receipts): Output receipts may carry a role-name lookup kind that older binaries cannot decode.
// #9947 (-9947-m2a-replayable-output-diagnostics): Output products record effective composition limits and reserve a new version for replayable diagnostics.
// #9995 (-9995-scala-library-owner-inventories): Scala companion apply, String applicability and known-head refutation change Scala library call answers.
// #5658 M8 step 1a (-5658-python-native-definition-dispatch): Python definition dispatch and value identity answer from the native selected resolution, so retained Python policy answers change.
// #10181 (-10181-go-multi-result-call-identity): the Go typed-var identity proof selects a call result slot by ordinal, so typed-local assignments of multi-result calls become proven.
// #9947 M2b part 1 (-9947-m2b-selector-gap-content): certified source-only selector gaps type endpoint completeness as content, and selector memo hits replay their reads, so retained Output publication and receipts change.
// #10384 (-10384-misspelled-jsx-intrinsic-tags): js/misspelled-identifier excludes intrinsic JSX tag names, so retained policy answers change.
// #10385 (-10385-caller-decided-external-member-access): external JVM member access is decided per caller, so member and dispatch answers change.
// #5658 M8 P1 (-5658-python-classmethod-receiver-gaps): a proven classmethod receiver discharges its own unannotated-parameter gap, so retained Python member answers change.
// #5658 M8 P2 (-5658-python-annotation-application-heads): subscripted and union annotations name their outer class or members, so retained Python member and dispatch answers change.
// #8675 S3 (-8675-s3-scala-term-path-heads): Scala term-path heads see imports, qualified routes select external JVM members, and a decided member retires its own qualified-type gap, so Scala qualified reads and overload answers change.
// #10388 (-10388-jvm-declaration-scoped-producer-gaps): declaration-scoped JVM producer warnings no longer make every query incomplete, so retained policy completions change.
// #7643 (-7643-supertype-argument-projection): a parameterized Java actual is projected onto a different generic owner through its declared supertype path, so retained call answers change.
// #9925 M1a (-9925-rust-ownership-unknown-projections): guarded pattern projection candidates.
// #10386 (-10386-known-misspelling-typo-table): js/misspelled-identifier reports only parts a pack-supplied typo table lists, and nothing without one, instead of edit-distance guesses.
// #10266 (-10266-capped-output-prefix): a capped Output run keeps the completed anchors' products on a later budget stop, and the finding and witness allowances count only findings that survive secondary suppression, so capped runs return different findings.
// #10433 (-10433-python-external-base-not-inference-failure): imported external Python bases are external, not failed inference.
// #9947 M2b part 2 (-9947-m2b-snapshot-execution-cause): an Unsupported snapshot status in the incomplete-relation promotion branch is content unless the snapshot is execution-dependent, so retained Output publication changes.
// #10445 (-10445-scala-parameter-clause-activation): a Scala parameter activates after its own clause, changing retained resolution and dispatch answers while #7262 is open.
// #5658 M8 P3 (-5658-python-callee-callable-result-only): a Python call's callee carries only the callable result, so retained Python member and dispatch answers change.
// #9224 (-9224-go-target-keyed-reverse-match): the Go selected target match ignores a definition only when stored routes prove it cannot be the target, so selected reverse, usage, and policy answers can change.
// #7262 (-7262-composition-memo-hit-receipts): composition run-memo hits for dispatches, evidence and std builtins replay their fill receipts, so units stored without those reads are discarded.
// #10106 (-10106-go-external-member-unprovided): a written Go type that no active declaration provider supplies a unique owner for stays open instead of completing empty (value members are #10184), so retained Go edge completeness changes.
// #9947 per-unit commit (-9947-interior-snapshot-causes): a witness run that records no witness reports its interior's cause, and a lost value-flow snapshot keeps a budget stop or a cancellation as its cause instead of Provider, so retained incomplete evaluation diagnostics change. Output publication also changes: an unstable execution or a truncated nested barrier row is no longer published, and publishable siblings of refused units are now stored, so units stored under the earlier rules are discarded.
// #5658 M8 P5 (-5658-python-module-alias-qualifier): a Python qualifier assigned once from a module reference is a namespace, so retained Python member, definition, class-set and dispatch answers change.
// #10400 (-10400-file-local-promotion-status): the incomplete-relation promotion takes its status and cause from the head's own file-local projection instead of the workspace snapshot, so retained Output refusals, rendered statuses and completion reasons change.
// #10020 (-10020-jvm-member-selection-not-lexical): a Scala or Kotlin member-selection leaf resolves through its receiver instead of the same-named local being declared, so retained definition and call-target answers change while #7262 is open.
// #10496 (-10496-python-assumed-cpython-toolchain): a Python workspace that declares no CPython version activates the stdlib packs for an assumed 3.13.5, so retained Python member, dispatch and pack-decision answers change.
// #5658 M8 P4 (-5658-python-qualified-class-definition-identity): the definition of a nested class reached through its owner reports the class when only its unproven creation is open, so retained Python definition, class-set and dispatch answers change.
// #10001 (-10001-typestate-incompleteness-gaps): a typestate root unit stores the typed gaps that made it inconclusive, which the run reports as diagnostics, in place of bare incomplete reasons.
// #7860 (-7860-receiver-type-argument-substitution): a native Java receiver's type arguments are substituted into the selected external member's formals and return type, so retained call answers and chained receivers change.
// #7262 F7 (-7262-rust-walk-cache-hit-receipts): Rust walk-cache hits replay their fill receipts, so units stored without the replayed walk reads are discarded.
// #10466 (-10466-rejected-return-member-content-gap): a rejected return member is a content gap (coverage Open, no execution marker) instead of a Truncated snapshot, so retained policy answers that read the snapshot or its stored head change.
// #10000 (-10000-java-external-constructor-families): an external Java constructor family that arity alone does not select binds its overload from argument types, so retained constructor call answers change.
// #9855 1b: invalidate policy products retained before close-match finding attribution.
// #9991 (-9991-mapped-summary-effects): an effect-bearing external summary binds through a keyword call's actual-to-formal mapping instead of failing model compilation, so retained ModelUnavailable candidate boundaries change.
// #7860 slice 2 A (-7860-callable-member-identity): a native Java external method whose name a non-public field shares keeps its member identity, so its declared result types enclosing calls and retained call answers change.
// #10399 (-10399-scoped-source-binding-refusals): an Output carries only the source-binding refusals of the frontier matches it consulted, and a refusal that the semantic input alone decides is content, so retained Output publication and the refusals stored with an Output change.
// #9987 (-9987-transform-output-port-placement): a composed taint transform from a call input to a result of a call with arguments is placed on that call, so retained transformed-label findings and completion change.
// #9981 (-9981-csharp-single-overload-applicability): a call whose actual provably cannot convert to the formal of the only layout-compatible model member no longer binds to it, and a Java owner's inventoried supertype now proves reference widening that an authored edge list omits, so retained C# and Java model call bindings and conversions change.
// #10539 (-10539-simultaneous-alternatives-join): the alternatives of one event join instead of each killing the last, so retained type-flow, taint and field-slot answers that lost an arm of a returned join change.
// #10432 (-10432-binding-substituted-call-conversions): native Java call-row conversions are proven against the selection's type-argument bindings, so retained conversion statuses and call-binding answers change.
// #5658 M8 Python native type switch (-5658-python-native-type-switch): Python type flow takes native type answers, so retained Python class-set, field, dispatch and finding answers change.
// #10560 (-10560-fallback-budget-value-restore): an abandoned sliced taint attempt no longer leaks its budget refusals or memo charges into the full fallback, and a semantic refusal beside kept products restarts the cold loop, so retained Failed answers near a budget limit change to the from-scratch Inconclusive.
// (-configuration-scalar-decoding): configuration value filters decode TOML scalars, JSON booleans, numbers and null, and literal XML CDATA, and an undecodable scalar answers incomplete, so retained configuration answers change for unchanged inputs.
// #9332 (-9332-omitted-saved-default-bindings): a call that omits formals with published saved defaults binds completely, so ICFG transfer completeness changes.
// #9863 M2: Rust binding identity and access completeness change retained rows.
// #10530 (-10530-scratch-admissions-closed): the strong-update question closes its scratch evidence admission, so a stored Output unit no longer carries it in its retained census and a run is no longer stopped by earlier units' scratch rows.
// #10596 (-10596-rust-manifest-file-identity): record the owning manifest on Rust file reads.
// #10582: interface boxing separates copied Go caller identities.
// #10403 (-10403-unit-scoped-semantic-budget-stop): a semantic budget stop is attributed to the Output unit whose discovery it truncated, and the units after it are judged on their own refusals, so a policy run that used to fail whole reports an inconclusive run with the findings of its other units, and stored evaluation rows of such runs are discarded.
// #10229 (-10229-csharp-member-form): C# member_targets rows gain query-time member_form and trivial_property values, changing retained rows for unchanged inputs.
// #10689: semantic model evidence ranks within each language family.
// #10563 (-10563-reference-prefix-alternative-paths): a read that continues through a cell a reference was stored into follows the stored object, and reports a store it cannot follow as partial, so retained value-flow and taint answers change.
// #8804 (-8804-relayed-exceptional-returns): a call's exceptional continuation relays its thrown value to the caller's exceptional-return port.
// #10694 (-10694-go-refused-file-graph-complete): a Go source that admission refuses after parsing is a named graph exclusion again, so one refused file no longer empties the workspace's Go graph and its inventory answers change.
// #10052 (-10052-csharp-fence-dispositions): C# Fenced pack owner and member-family dispositions change retained policy answers.
// #10683 (-10683-identity-prefix-stores): an identity field copy (an initialized let copying its initializer) no longer redirects a longer access back into its own cell, so value-flow snapshots that truncated now complete, and retained value-flow and taint answers change.
// #10783 (-10783-unresolved-call-subject-continuation): a typestate subject passed exactly to an unresolved call keeps a possible normal continuation, so retained root products gain Possible terminal findings that used to vanish.
// #10759: owned-site conditional selection changes policy reads, charges and site-attributed completeness before call binding.
// #10812 (-10812-model-overload-applicability-by-type): a call site's written actual count no longer selects the model overload with that declared parameter count; Java and C# overloads with different binding layouts are selected by the actuals' types or reported incomplete, and a zero-argument Java source call actual is typed by its declared return, so retained model call bindings, sink endpoints and summary closures change.
// #10530 M2: Output units use independent resident ledgers and replay without batch residency.
// #8854 (-8854-absent-language-locators): a qualified locator that fails where the analyzer has no file in its plan's languages stays unresolved instead of leaving the policy not run, so retained not-run evaluation rows of such policies change to complete.
// #9925 M1b2 (-9925-rust-admitted-binder-discharge): a selected Poem field binder is a matched-value source and its witness records the admission, so retained Rust policy answers change for unchanged source and pack bytes.
// #10687 B (-10687-conversion-weakened-call-transfers): a Rust call whose argument conversion may run a user Deref keeps its transfer and modeled boundary incomplete, and composition reads that answer outside the Dispatch answer digest, so retained taint, typestate and value-flow answers change.
// #10770 slice 1 (-10770-method-operator-result-types): Rust non-generic method results and primitive operator results are typed, so fewer argument conversions are treated as may-run-user-code and retained taint, typestate and value-flow answers change.
// #10846 (-10846-unproven-conversion-continuation): a resolved call whose argument conversion may run a user Deref keeps a possible continuation with the subject unchanged, so retained typestate root products gain possible terminal paths and findings.
// #10770 slice 2a (-10770-self-and-model-result-types): Self method results and model-backed std types such as String through Clone::clone are typed exactly, so fewer argument conversions are treated as may-run-user-code and retained answers change.
// #10774+#10830: only Cargo.toml contributes manifest gaps copied into unit summaries.
// #10470: read completeness of JVM lookups changes for unchanged inputs.
// #10770 slice 2b (-10770-generic-result-types): impl-parameter and model generic method results are typed exactly, so fewer argument conversions are treated as may-run-user-code and retained answers change.
// #10802 (-10802-log-package-identity): log macros are trusted only when the exposed dependency resolves to package log, path-qualified log macro format operands are proven no-coercion, and an unknown macro argument list now counts as may-run-user-code, so retained answers change.
// #10770 slice 2c (-10770-operator-output-types): workspace and model operator results are typed through the operator trait's Output, so fewer argument conversions are treated as may-run-user-code and retained answers change.
// #9687 E2 (-9687-e2-rust-tail-gap-removal): removing the blanket tail gap changes retained Rust completeness and policy answers.
// #10770 (-10770-alias-type-expansion): shared alias interpretation changes retained type answers.
// #10953: target dependency tables and destination library names change Rust crate summaries.
// #4307: complete std Deref summaries admit receiver flow and conditional-guard carrier mapping.
// #9737 c2 (-9737-route-completeness): Rust usage and reference answers come from per-question route derivations, and a partial crate answers unknown where the whole route index answered a fail-open negative, so retained policy answers change for unchanged inputs.
// #9766 (-9766-block-dead-fallthrough): dead block normal ends no longer define values, changing retained Rust flow answers.
// #9402 (-9402-csharp-member-identity-discharge): a query-time resolver proof retires C# member and indexer identity gaps, so taint completeness changes for unchanged bytes.
// #10269 (-10269-rust-pattern-glob-braced-struct): a Rust pattern name under a glob import is Unknown and a braced-struct name binds, so retained Rust completeness and policy answers change.
// #11022 J1: Java instance and non-void method footprints are claimed, so protocol summaries are served for Java roots that answered Incomplete(SemanticGap).
// #11014: Java try-with-resources close selection changes policy call answers.
// #10952 (-10952-recorded-inventory-lookups): Rust trait inventory reads are recorded selected-live lookups; older receipts lack them, and the interim markers are removed.
// #11036 (-11036-log-shadow-refusal): a crate-local `log` item shadowing the log crate refuses log macro admission, so retained answers change.
// #10985 M1: candidate completion boundaries change selector admission receipts.
// #9737 step d (-9737-step-d-conversion-routes): Rust call-conversion proofs (std operator identity, prelude and crate-root questions) read per-question routes and abstain on a partial crate, where the whole route index answered, so retained policy answers change.
// #11069 (-11069-declaration-facts-hit-receipts): Rust declaration_facts cache hits replay the fill's complete receipt; older warm receipts lack its manifest, file, absence and overlay reads.
// #11060 (-11060-unplaced-module-topology): a declared Rust module without a source blob keeps its topology partial, so retained Rust completeness and policy answers change.
// #8297 (-8297-csharp-model-extension-methods): C# reduced-form calls bind model-declared extension methods, so C# dispatch and call-binding answers change.
// #8430 step 2: extern alias facts and alias-qualified routes change retained C#
// call-binding answers; above master full v818 / read v817: full v819 / read v818.
// Model alias target expansion and #11043 shared Named substitution/work alter
// canonical Rust proofs; coordinator assigned full v810 / read v809.
// Alias expansion merge: both parents full v810 / read v809; max + 1 gives full v811 / read v810.
// Final alias merge: parents full/read 811/810 and 813/812; max + 1 gives 814/813.
// Final model-alias submission merge: both parents full/read 814/813; max + 1 gives 815/814.
// Mechanical alias submission merge: parents 815/814 and 818/817; max + 1 gives full/read 819/818.
// Batch merge retains the base #8430 token, then the incoming model-alias token.
// #11111: certified-absent Rust modules preserve broad completeness; append
// its token after this lane's earlier named-open-symbol token.
// #11111: certified-absent Rust modules preserve broad completeness; the merge
// appends its token after the already-landed model-alias token.
// #8430 step 2 (-8430-extern-alias-facts): C# extern alias declarations are recorded as facts and alias-qualified names resolve through them, so retained C# policy answers change.
// #10342 (-10342-global-using-enumeration-evidence): only extraction gaps that can hide a C# global using open the compilation's global-using inventory, so retained C# policy answers change.
// #8430 step 3 (-8430-alias-qualified-consumer): C# `X::` routes see aliases only; a namespace alias continues the route, a type alias is CS0431, an extern alias stays an open boundary, a conflict is incomplete, and alias absence requires a complete global-using read B, so retained C# policy answers change.
// #11089: unready Rust inventories change candidate admission and completion receipts.
// #11146: qualifying-type unit discharge changes seeded policy-unit merge results.
// #10985 M2a (-10985-m2a-subject-selection): typestate compilation binds Selected candidates and retains Undecided ones instead of failing the whole selector, and its fingerprint carries the undecided identities, so evaluation answers change.
// #4967 C (-4967-residual-alias-parameters): the Rust ? residual proof binds generic alias parameters. Its gap discharge reaches units through procedure relations, not a recorded Dispatch answer digest, so retained Rust completeness and policy answers change.
// #11087 (-11087-owner-focus-definition): owner and generic-argument navigation retain native type boundaries instead of the containing callable.
// #7314 M6a1 (-7314-m6a1-csharp-declared-types): C# declared type slots publish, and predefined type keywords lower as global::System types, so retained C# policy answers change.
// #11131 (-11131-undecided-row-predicates): RQL row-predicate evaluation withholds undecided source-property rows and reports Content incompleteness.
// #4967 C slice 3 (-4967-residual-await-call): an awaited direct async fn call types the Rust ? residual, and a sync call on an async callee no longer does, so retained Rust completeness and policy answers change.
// #11169 (-11169-resolved-callee-provenance): RQL call-shape rows refine a Rust method call whose stored callee_provenance is unknown to declared when the call target resolves, ungapped, to one declared method on a closed bound receiver. Policy answers that filter on callee_provenance change for unchanged bytes.
// #7314 M10a0: per-framework symbol environments change branch selection.
// #10497 (-10497-external-intermediate-supertypes): JVM dispatch families include workspace overrides reached through external intermediate supertypes and open when a supertype resolves to nothing, so retained Java and Kotlin dispatch and policy answers change.
// #10985 M3: exclusions scope typestate acquisitions before enumeration; auxiliary selectors remain global.
const POLICY_SUBSTRATE_EPOCH: &str = "bifrost-policy-unit:substrate:5113-returned-refinement-census-v4-5495-branch-work-budget-5496-branch-reference-proofs-5498-permitted-handler-raises-5506-explicit-tuple-return-shapes-5310-set-projections-5338-builtin-shapes-5246-endpoint-closure-4811-python-rule-fact-diagnostics-4321-external-iterator-anchors-5339-assignment-binder-origins-5339-binder-activation-5339-read-relative-initializers-5385-loop-read-diagnostics-5227-icfg-barriers-5510-python-hierarchy-diagnostic-locations-5534-python-tuple-property-proof-5532-python-generator-headers-5543-python-none-only-tuple-proof-5559-python-local-function-return-proof-5598-python-module-initializers-5511-python-modeled-runtime-ancestry-5721-python-local-import-bases-5738-intrinsic-root-evidence-5745-python-runtime-class-binding-5751-python-class-object-aliases-5812-iteration-value-origins-5113-reference-inventory-ownership-5920-performed-source-lane-5964-comparison-chain-demand-proof-7186-compact-constructor-bindings-7289-field-initializer-reads-7150-go-call-result-counts-7219-rust-concrete-receiver-closed-7183-unproven-family-dispatch-7179-incomplete-family-edges-and-coverage-2445-root-allotment-4365-javadoc-tag-anchors-7379-dereference-store-operations-7344-7345-csharp-compound-writes-5658-single-writer-identity-5658-structural-module-mutations-7373-csharp-contextual-keyword-binders-5658-python-attribute-space-owners-5658-python-argument-independent-calls-7371-nonlocal-branch-distinction-7372-initializer-body-relations-7179-java-unread-ancestors-4365-shared-statement-facts-7107-content-diagnostic-units-7220-php-terminal-case-fold-rust-deref-receiver-steps-7226-7464-csharp-incoming-overload-partition-7368-7369-csharp-equals-argument-identity-7150-open-member-calls-7340-live-region-overwrite-veto-7520-go-interface-dispatch-references-5658-python-global-writer-identity-5658-python-native-member-targets-7548-configuration-skips-bifrost-dir-analysis-quicksilver-round12-boolean-contexts-binder-spans-7202-classified-summary-identity-7547-java-string-literal-values-analysis-quicksilver-round12-fact-analyzers-7471-go-short-var-redeclaration-7386-conditional-compilation-regions-7341-7342-go-remainder-comma-ok-7617-go-direct-type-shapes-7343-go-static-type-failure-branches-7393-unproven-nonempty-failure-branches-7470-go-visible-binding-shapes-7616-go-modeled-package-result-unknown-analysis-quicksilver-round12-config-lookup-7518-go-undecided-receiver-candidates-7578-branch-conditioned-sanitizers-7618-java-creation-receiver-site-7560-csharp-row-backed-models-7348-7349-7369-java-compound-static-patterns-4379-m3b-csharp-statement-facts-7642-witness-budget-incomplete-5658-python-unplaced-file-references-7516-go-constructor-shadow-7673-python-qualified-module-members-7619-java-implicit-external-inherited-calls-7620-java-wildcard-sibling-applicability-7578-java-observed-value-type-7578-guard-writer-reachability-7735-binder-declaration-sites-5658-python-import-occurrence-kinds-7781-synthetic-members-completeness-7509-go-declaration-value-types-7755-refused-alternative-before-budget-3494-ruby-member-closure-7789-indexed-import-destinations-7817-external-supertype-kind-7849-java-external-owner-observed-type-7509-go-native-binding-proofs-2445-m4a-workspace-facts-qs13-flow-go-no-return-method-expressions-7350-nonbinding-rhs-distinct-qs13-flow-summary-payload-accounting-qs13-flow-typestate-byte-accounting-7918-go-field-selector-addressability-7536-initialization-retained-gaps-7915-flow-slot-identity-7508-csharp-conditional-branch-conversions-7803-external-field-value-types-2445-m4b-property-gaps-qs13-flow-store-error-kind-context-qs13-flow-taint-composition-quality-7779-exact-selection-owner-inventory-qs13-flow-call-transfer-canonical-order-7972-go-cross-file-global-self-assignment-7509-go-model-authority-7755-dead-value-liveness-7868-closure-open-relations-7876-query-incompleteness-scope-7509-go-relative-source-imports-qs13-flow-value-flow-survivors-7351-go-error-method-set-proof-7886-nested-budget-stop-propagation-qs13-flow-field-slot-source-kinds-8036-go-native-external-callee-identity-qs13-rql-pending-cleanup-nested-scope-qs13-rql-python-loop-exit-and-docstring-blocks-7968-go-satisfaction-membership-8108-java-inventory-stable-replay-qs13-rql-configuration-property-ancestor-7509-g1b-incomplete-import-owner-8097-assignment-flow-gap-scope-3800-static-rooted-property-bases-7362-query-obligation-ledger-7505-member-ids-carry-signature-7187-jvm-type-parameter-bindings-4379-m6-csharp-static-array-definitions-8146-boolean-patterns-unkinded-targets-4379-m6-csharp-nested-if-misleading-indentation-2445-content-partial-diagnostics-8148-binary-authority-inputs-6664-incomplete-descendant-queries-4379-m6-csharp-rethrow-throw-sites-8153-ambiguous-binding-no-proven-target-8000-jvm-on-demand-external-candidates-qs13-rql-order-independent-fixed-points-7509-g1b-callable-result-slots-7391-go-type-assertion-receivers-7153-cpp-field-guard-definitions-6945-curated-star-child-binding-8154-recursive-empty-arm-statements-7424-java-enum-switch-proof-7577-scala-cast-expression-types-8242-taint-endpoint-dominance-qs13-rql-file-joins-and-selected-property-admission-7240-imported-constructor-receivers-6234-kotlin-implicit-receiver-values-qs13-rql-source-and-language-survivors-8262-model-hierarchy-missing-endpoint-8264-go-predeclared-result-types-7509-g1b3-pointer-result-field-8147-m4a-csharp-preprocessor-decisions-8290-warm-closure-discharges-2445-content-cause-precision-7314-c1-4b-csharp-native-demand-qs13-rql-python-search-survivors-7509-b-unexported-pointee-owner-8167-java-callable-family-evidence-8222-scala-implicit-root-order-8300-resolved-value-proven-near-miss-8305-field-write-call-ports-8201-stable-capped-index-reads-7314-c1-4d1-csharp-qualified-heads-7314-c1-4d2-csharp-aliases-7314-c1-4d3-csharp-using-tiers-8403-rust-reverse-applicability-gaps-7314-c1-5a1-csharp-transient-membership-qs13-policy-source-survivors-7027-s2b-jvm-native-ancestors-7314-c1-5a2-csharp-global-aliases-qs13-policy-flow-survivors-7314-c1-5b-csharp-global-globs-7027-s2c-hierarchy-completeness-8411-static-openness-is-content-2445-unsupported-member-family-unresolved-8287-merged-limit-partition-7509-g1b3-exact-binding-identity-7314-c1-5c-csharp-root-closure-8385-position-free-read-keys-qs13-policy-catalog-identity-survivors-7314-c1-4e-ad1-csharp-membership-unproven-7027-s3-native-descendants-7761-memo-fill-own-completeness-8415-enclosing-type-parameters-8496-plan-provider-free-on-demand-packages-8306-await-value-transfer-8309-csharp-type-literal-values-7366-field-write-source-member-evidence-8308-csharp-call-points-string-guards-8388-caller-inventory-coverage-8486-stable-content-producer-diagnostics-8457-rust-unenumerable-dispatch-8453-go-method-unenumerable-dispatch-8513-scaled-retention-budget-8546-model-edit-recomputes-units-8402-go-parse-time-ir-7314-c1-4e-ad2-csharp-per-file-membership-8333-scala-compiler-root-owner-8279-scala-scope-shadowing-8147-m4b-csharp-parse-variants-7234-php-static-scope-dispatch-8579-native-parse-time-ir-7750-java-guarded-switch-edges-8283-structural-result-type-identity-7509-g1b3-f-nested-call-arity-8632-csharp-parent-relative-open-items-8602-exit-only-exceptional-routes-8586-one-budget-at-materialization-8665-scala-import-bridge-boundaries-8516-package-member-owner-providers-7314-csharp-method-applicability-open-8705-scala-implicit-root-own-gap-8147-m4c-csharp-unseen-branches-7314-demand-half-open-outcome-8667-go-nested-arity-gap-7509-g1b3-g-untyped-receiver-native-count-7027-s2b0-implicit-supertypes-7960-js-call-throw-catch-binding-8790-go-path-index-stable-gap-replay-7800-heuristic-structural-matches-8025-js-namespace-static-loads-8745-pre-kotlin-lambda-parameter-binders-7314-ad3b-csharp-get-path-of-file-above-8830-csharp-nuget-build-transitive-imports-8836-revert-js-call-throw-catch-binding-8831-csharp-target-property-scope-8845-csharp-multi-target-razor-paths-7509-3a-native-call-application-roles-8872-js-ts-package-module-identity-7509-m5b1-native-selector-refinement-8856-budget-independent-base-replay-8388-icfg-go-builtin-assumptions-8389-prefix-merge-suffix-8823-jdk-pack-type-parameter-scope-7509-m5b2-native-allocation-refinement-8870-composed-entry-points-7509-function-field-call-application-8866-rust-unwrapped-receiver-8884-rust-selected-import-reads-8822-csharp-inventory-closed-derivations-7509-m5b3-native-nested-call-result-counts-7869-package-boundary-per-alternative-8898-cancelled-procedure-openness-7509-retire-go-expression-inference-8803-csharp-enclosing-namespace-scope-8870-composed-store-ends-7619-java-generic-result-receivers-8487-java-on-demand-package-outcomes-8992-jvm-on-demand-declaration-admission-8389-charge-reused-units-8389-union-seed-local-suffix-7509-go-structural-signature-identity-7509-m5b4b-native-function-value-proof-8996-diff-base-reliability-7509-m5b4a-selected-aggregate-owner-8963-go-result-obligation-coverage-8870-composed-flow-policies-8991-rust-let-copy-allocation-2508-native-composed-effects-8978-rust-branch-value-join-7804-java-fqn-expression-prefix-8389-intersect-prefix-reuse-8896-composed-member-call-bindings-8389-typestate-root-fit-9013-rust-call-guard-truthy-7314-m1f-java-common-import-context-8870-composed-conditional-sanitizers-9063-go-certified-method-collision-9084-declaration-finding-anchors-8741-implicit-root-edges-order-independent-8834-root-presence-read-key-8675-pre-closed-relation-discharge-replay-8386-value-flow-neutral-endpoint-ids-8870-store-ended-candidates-9127-mount-free-value-flow-plan-identity-8896-returned-member-ports-8940-post-call-heap-ports-8896-icfg-member-call-bindings-9162-partial-flow-seed-canonicalization-8962-semantic-artifact-window-admission-8893-rust-selected-operation-reuse-9196-closure-invocation-certificates-9230-rql-native-caller-inventory-8389-native-output-units-9060-typed-round-ready-queue-9195-native-scala-alias-parents-9220-jvm-renamed-member-imports-6291-native-java-call-binding-corrections-6792-scala-bare-term-bindings-8389-file-local-set-minuend-8388-go-composed-taint-7654-scala-anyref-object-members-9276-store-witness-source-sites-8389-root-union-file-local-set-8386-go-composed-value-flow-8870-go-conditional-composition-8826-csharp-undecided-scan-receipt-7509-go-sole-alias-owner-9195-scala-reference-package-contexts-9323-kotlin-jdk-static-calls-8386-composed-rowless-sink-artifacts-9270-csharp-yield-normal-continuation-7726-kotlin-native-call-evidence-8826-query-memo-admission-8386-typestate-composition-9263-rust-copy-absence-9277-go-selected-context-reconciliation-7960-reland-js-call-throw-definition-alternatives-9378-indexed-modeled-call-results-9378-composed-result-activation-9323-kotlin-jdk-constructor-callees-9378-go-pointer-handoffs-9412-scala-local-package-precedence-7509-go-channel-direction-identity-9330-php-element-concat-flow-9331-php-string-interpolation-flow-9203-rust-owned-receiver-events-9324-scala-jdk-call-targets-9438-decorator-argument-arity-9438-decorator-comment-parens-9431-lifecycle-coverage-claims-9060-semi-naive-typed-rounds-8723-read-reasons-reach-structural-answers-9432-go-modeled-imported-formal-authority-9486-modeled-producer-origin-9532-java-external-formal-type-arguments-7365-declaration-attribute-capability-5658-python-native-production-switch-8389-set-prefix-reuse-9561-negated-feature-capability-4379-m4b-csharp-declaration-attributes-9522-receiver-incomplete-candidates-9557-native-java-unread-ancestors-8870-java-static-import-reverse-completeness-8389-typestate-set-union-slice-9595-prefix-coverage-reasons-8870-java-nested-reverse-owners-8675-s2-java-type-frontier-authority-9614-attribute-kind-inheritance-9612-unclassified-reference-kinds-9546-m1a-selected-import-authority-9582-prefix-intersect-short-circuit-9563-semi-naive-query-node-obligations-8870-java-reference-callable-context-9575-python-mutation-read-admission-7857-modeled-member-candidates-9447-structured-formal-roles-9002-jvm-lexical-head-blockers-9617-reference-kind-facets-7040-rust-gap-diagnostic-path-5658-python-file-local-lowering-8837-csharp-configuration-presence-9779-cpp-recovered-lexical-formals-9183-typestate-alias-guards-9658-composed-terminal-provenance-9743-composition-call-result-origin-9612-field-access-facets-8500-certified-owner-targets-and-reverse-obligations-9810-go-field-access-facets-9550-call-closure-honest-summaries-9651-formal-member-overwrite-9835-rust-positional-generic-results-9868-unknown-binder-source-refusal-9784-stored-semantic-ir-read-admission-9863-rust-first-unreachable-region-9773-java-assignment-operator-9746-composition-root-publication-9687-e1-rust-result-producers-9783-selected-import-owner-publication-9840-warm-activation-carry-9934-rust-wildcard-assignment-discard-9852-go-external-leaf-certification-9900-java-override-parameter-types-9971-edge-match-candidates-9677-kotlin-explicit-import-receivers-9879-go-scoped-call-control-claims-9324-inapplicable-external-access-gaps-10014-receiver-taint-rows-9971-edge-provenance-9918-rust-local-import-routes-9444-rust-pattern-capture-contract-9937-partial-summary-positive-transfers-9546-java-usage-evidence-receipt-replay-5658-python-with-suppression-candidate-edges-10042-rust-missing-target-roots-9954-go-qualified-callees-binary-coverage-9866-rooted-call-reachability-9319-ruby-gem-lock-activation-9863-localized-statement-reachability-9794-go-deferred-call-result-pointer-9479-scala-parameterless-selection-calls-9423-jvm-external-supertype-targets-10021-creation-type-from-qualifier-10096-composed-witness-seed-10050-configuration-directory-field-10058-implicit-current-object-identity-10058-transparent-wrapper-identity-10050-scoped-configuration-absence-9863-rust-feasible-literal-guards-10061-go-method-call-result-pointer-10045-authored-family-precedence-9559-request-owned-carried-anchors-7708-declared-type-argument-transport-10052-dotted-member-qualified-lookup-10166-inventory-excludes-analyzer-cache-10161-go-typed-var-call-result-identity-10168-reaching-writer-at-capture-9737-recorded-derivation-inputs-10058-receiver-determined-member-identity-9642-protocol-coverage-admission-9766-separated-join-members-9324-scala-reference-conversions-10097-role-name-inventory-receipts-9947-m2a-replayable-output-diagnostics-9995-scala-library-owner-inventories-5658-python-native-definition-dispatch-10181-go-multi-result-call-identity-9423-kotlin-java-getter-properties-9947-m2b-selector-gap-content-5658-python-classmethod-receiver-gaps-10384-misspelled-jsx-intrinsic-tags-10385-caller-decided-external-member-access-5658-python-annotation-application-heads-8675-s3-scala-term-path-heads-10388-jvm-declaration-scoped-producer-gaps-9925-rust-ownership-unknown-projections-7643-supertype-argument-projection-10386-known-misspelling-typo-table-10266-capped-output-prefix-10433-python-external-base-not-inference-failure-9947-m2b-snapshot-execution-cause-10445-scala-parameter-clause-activation-5658-python-callee-callable-result-only-9224-go-target-keyed-reverse-match-7262-composition-memo-hit-receipts-10106-go-external-member-unprovided-9947-interior-snapshot-causes-5658-python-module-alias-qualifier-10400-file-local-promotion-status-10020-jvm-member-selection-not-lexical-7262-rust-route-memo-hit-receipts-10496-python-assumed-cpython-toolchain-5658-python-qualified-class-definition-identity-10001-typestate-incompleteness-gaps-7860-receiver-type-argument-substitution-7262-rust-walk-cache-hit-receipts-10466-rejected-return-member-content-gap-9992-php-array-literal-elements-10000-java-external-constructor-families-9855-close-match-1b-finding-attribution-9991-mapped-summary-effects-9988-go-conversion-origin-validation-7860-callable-member-identity-10399-scoped-source-binding-refusals-9987-transform-output-port-placement-9981-csharp-single-overload-applicability-10088-depth-bound-reached-9869-go-constrained-source-inventory-callers-10539-simultaneous-alternatives-join-10432-binding-substituted-call-conversions-5658-python-native-type-switch-10560-fallback-budget-value-restore-configuration-scalar-decoding-9332-omitted-saved-default-bindings-9863-rust-binding-access-facts-10530-scratch-admissions-closed-10596-rust-manifest-file-identity-10582-go-interface-boxing-conversions-10403-unit-scoped-semantic-budget-stop-10229-csharp-member-form-10689-rank-within-language-family-10563-reference-prefix-alternative-paths-8804-relayed-exceptional-returns-10694-go-refused-file-graph-complete-10052-csharp-fence-dispositions-10683-identity-prefix-stores-7314-ad3d-ordered-msbuild-properties-10783-unresolved-call-subject-continuation-10759-procedure-scoped-guard-selection-10812-model-overload-applicability-by-type-10530-unit-scoped-ledger-8854-absent-language-locators-10357-file-program-evidence-9925-rust-admitted-binder-discharge-10356-derived-sdk-default-compile-10687-conversion-weakened-call-transfers-7314-ad3d-msbuild-condition-short-circuit-8430-csharp-grammar-0-23-9-10761-possible-overload-families-10770-method-operator-result-types-10881-folded-operand-arms-10846-unproven-conversion-continuation-10770-self-and-model-result-types-10774-manifests-only-cargo-toml-10470-per-lookup-dependency-gaps-10770-generic-result-types-10802-log-package-identity-10770-operator-output-types-9687-e2-rust-tail-gap-removal-10953-target-dependencies-and-lib-names-10770-alias-type-expansion-9737-route-completeness-10987-scoped-symlink-omissions-9766-block-dead-fallthrough-9402-csharp-member-identity-discharge-10269-rust-pattern-glob-braced-struct-11022-java-footprint-j1--4307-rust-std-deref-summary-chain-10989-closed-container-key-cells-11014-twr-close-member-selection-10952-recorded-inventory-lookups-11036-log-shadow-refusal-8296-csharp-exact-match-overloads-10985-m1-candidate-outcomes-11060-unplaced-module-topology-9737-step-d-conversion-routes-11069-declaration-facts-hit-receipts-8297-csharp-model-extension-methods-8430-extern-alias-facts-model-alias-target-expansion-11111-certified-absent-module-topology-10342-global-using-enumeration-evidence-8430-alias-qualified-consumer-11089-unready-inventory-incompleteness-qualifying-type-unit-discharge-10985-m2a-subject-selection-4967-residual-alias-parameters-11087-owner-focus-definition-7314-m6a1-csharp-declared-types-7314-m10a0-named-open-symbols-11131-undecided-row-predicates-4967-residual-await-call-11169-resolved-callee-provenance-7314-m10a0-per-framework-symbols-10497-external-intermediate-supertypes-10985-m3-typestate-seed-scope";
/// The epoch every unit key and the evaluation row key carry.
fn policy_substrate_epoch(lowering: StableDigest) -> StableDigest {
    StableDigest::sha256(format!(
        "{POLICY_SUBSTRATE_EPOCH}\u{1}{}\u{1}{lowering}",
        analysis_epoch_digest(),
    ))
}

#[cfg(test)]
pub(crate) fn substrate_epoch_before_8837(lowering: StableDigest) -> StableDigest {
    let previous = POLICY_SUBSTRATE_EPOCH.replace("-8837-csharp-configuration-presence", "");
    StableDigest::sha256(format!(
        "{previous}\u{1}{}\u{1}{lowering}",
        analysis_epoch_digest()
    ))
}

/// Which partition of the workspace one unit covers.
///
/// A `Seed` unit is keyed by the file its seed enumeration walked and the blob
/// that path resolved to, because the same path holding different bytes is a
/// different unit even when nothing else moved. `Whole` is retained for
/// loading legacy persisted products, but new widened evaluations do not mint
/// it: a widened run evaluates directly and publishes no unit.
///
/// A `Binding` unit is one seed file of one row binding of a relational
/// assertion policy. It names the binding beside the file, because one
/// relational policy runs one query per declared binding over the same seed
/// files: two bindings keyed by the file alone would be one key, and the
/// second binding's rows would be served from the first binding's unit.
///
/// An `AssertFile` unit is one subject file of an assertion policy. It carries
/// the digest of that file's subject rows beside the blob, because a subject
/// selector that bound different rows in the same bytes asked a different
/// question of the same file and must not be answered with the first
/// question's findings.
///
/// A `Selector` unit is one seed file of one selector of a policy that
/// compiles selectors: the file, the blob that path resolved to, and the
/// selector's own document path. The path is part of the key because one
/// policy compiles many selectors over the same seed files -- a typestate
/// policy's subjects, events, terminals and dependencies -- and two of them
/// keyed by the file alone would be one key, and the second selector's sites
/// would be served from the first selector's unit.
///
/// A `Root` unit is one solver root of a typestate policy: the file the root
/// procedure is declared in, the blob that path resolved to, and the root's
/// own checkout-independent semantic locator. The locator is part of the key
/// because one file declares many procedures and a typestate policy solves
/// each of them separately: two roots keyed by the file alone would be one
/// key, and the second root's findings would be served from the first root's
/// unit. It carries the compile that produced it beside the locator -- the
/// compiled protocol hash and binding-plan hash together -- because every
/// projection a root solve produces is sealed to those two hashes and the
/// projection authority drops a projection that names any other compile. A
/// root served across a compile boundary therefore reports nothing rather
/// than reporting something wrong, which is the one failure a store must not
/// have.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnitPartition {
    Seed {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    Binding {
        binding: Box<str>,
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    AssertFile {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        subjects: StableDigest,
    },
    Root {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        locator: StableDigest,
        compilation: StableDigest,
    },
    Selector {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        selector: StableDigest,
    },
    Prefix {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        cut: StableDigest,
        input: StableDigest,
    },
    Output {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        anchor: StableDigest,
        compilation: StableDigest,
    },
    Whole,
}

impl UnitPartition {
    /// The stable label of this partition kind.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Seed { .. } => "seed",
            Self::Binding { .. } => "binding",
            Self::AssertFile { .. } => "assert_file",
            Self::Root { .. } => "root",
            Self::Selector { .. } => "selector",
            Self::Prefix { .. } => "prefix",
            Self::Output { .. } => "output",
            Self::Whole => "whole",
        }
    }
}

/// Everything that decides whether two evaluations are the same question.
///
/// The policy's semantic hash and the family fix what is being asked, the
/// partition fixes over which content, and the three digests fix the engine
/// that would answer: the analyzer configuration folded into every content
/// identity, the active semantic-model set, and the analysis epoch every
/// persisted fact was derived under. A run that differs in any of them is
/// asking a different question and gets a different key rather than a wrong
/// answer.
///
/// The evaluation budget is deliberately not part of the key: callers with
/// different budgets share units. A unit produced under a budget cut holds a
/// correct, reported-incomplete subset, and which subset a cut returns is not a
/// contract, so a shared unit is never read as exact for any one budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyUnitKey {
    pub policy: PolicySemanticHash,
    pub family: PolicyAnalysisType,
    pub partition: UnitPartition,
    pub configuration: StableDigest,
    pub models: StableDigest,
    pub epoch: StableDigest,
}

/// What one unit produced.
///
/// A query unit's product is the projection of its rendered rows, their
/// evidence and the execution's counters, which is exactly what the merge and
/// the policy adapter consume. An assert unit's product is not rows at all: it
/// is what one iteration of the assertion per-file loop produced.
#[derive(Debug, Clone)]
pub(crate) enum PolicyUnitProduct {
    Rows(UnitExecutionResult),
    AssertFile(AssertFileProduct),
    Root(RootProduct),
    Selector(Box<SelectorProduct>),
    Prefix(String),
    Output(String),
}

impl PolicyUnitProduct {
    /// The rendered rows this product carries, or `None` when it carries a
    /// product of another shape.
    ///
    /// A caller that asked a rows-shaped question and got something else is
    /// holding a store that answered a different question, which is a load
    /// failure rather than an empty answer.
    pub(crate) fn into_rows(self) -> Option<UnitExecutionResult> {
        match self {
            Self::Rows(rows) => Some(rows),
            Self::AssertFile(_)
            | Self::Root(_)
            | Self::Selector(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The per-file assertion product this carries, or `None` when it carries a
    /// product of another shape.
    pub(crate) fn into_assert_file(self) -> Option<AssertFileProduct> {
        match self {
            Self::AssertFile(product) => Some(product),
            Self::Rows(_)
            | Self::Root(_)
            | Self::Selector(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The per-root typestate product this carries, or `None` when it carries
    /// a product of another shape.
    pub(crate) fn into_root(self) -> Option<RootProduct> {
        match self {
            Self::Root(product) => Some(product),
            Self::Rows(_)
            | Self::AssertFile(_)
            | Self::Selector(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The per-seed selector product this carries, or `None` when it carries a
    /// product of another shape.
    pub(crate) fn into_selector(self) -> Option<SelectorProduct> {
        match self {
            Self::Selector(product) => Some(*product),
            Self::Rows(_)
            | Self::AssertFile(_)
            | Self::Root(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The stable label of this product kind.
    pub(crate) const fn stable_label(&self) -> &'static str {
        match self {
            Self::Rows(_) => "rows",
            Self::AssertFile(_) => "assert_file",
            Self::Root(_) => "root",
            Self::Selector(_) => "selector",
            Self::Prefix(_) => "prefix",
            Self::Output(_) => "output",
        }
    }
}

/// What one iteration of the assertion per-file loop produced.
///
/// Exactly the file's contribution to the run's accumulators, and nothing
/// else: the findings its asserts violated, the typed reasons it could not be
/// concluded (empty when it was), the completion of every row query it ran, the
/// query diagnostics it raised, and what it scanned. The merge appends each of
/// these to the run-wide accumulator in path order, and the run then finishes
/// exactly as a whole evaluation finishes.
///
/// A file's iteration never returns both findings and reasons: a verdict over
/// an incomplete row set is never a pass and never a finding, so an unconcluded
/// file contributes no findings at all.
#[derive(Debug, Clone, Serialize)]
pub struct AssertFileProduct {
    pub findings: Vec<PolicyFinding>,
    pub unconcluded: Vec<PolicyIncompleteReason>,
    pub row_completions: Vec<CodeQueryCompletion>,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub work: CodeQueryExecutionWork,
}

/// What one iteration of the typestate per-root loop appended.
///
/// Exactly the root's contribution to the run's accumulators and nothing else:
/// the violations it projected, in the order the loop appended them; the typed
/// gaps its own analysis left, which become the run's incomplete reasons and
/// diagnostics; and what it added to the run's
/// counters, including the four request-wide finding lanes it consumed. The
/// merge appends each of these in root order into the same accumulators a
/// whole evaluation fills, and the run then finishes exactly as a whole
/// evaluation finishes.
///
/// The projections rather than the findings they become: one iteration of the
/// loop appends projections, and the batch that turns them into findings runs
/// once over every root's, under the seal minted for this evaluation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RootProduct {
    pub findings: Vec<TypestateProjectedFinding>,
    pub gaps: Vec<TypestateGap>,
    pub work: RootWork,
}

/// What one root's iteration added to the run's counters, and what it took out
/// of the lanes every root of the evaluation shares.
///
/// The first five fields are the run's reporting counters. Everything after
/// them is a shared allowance this root consumed: the four `finding_*` lanes
/// of the request-wide finding budget, the solver and semantic ledgers the
/// solve charged, the execution budget's materialized files and traversal
/// steps, and the artifact leases the root's window committed. They are part
/// of the product because those allowances are shared: a run that reused this
/// root still has to charge what the root's own solve cost, or a later root
/// would see an allowance no whole evaluation would have given it and the
/// sliced run would reach a lane later than the whole run does.
#[derive(Debug, Clone, Copy, Default, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootWork {
    pub reached_rows: u64,
    pub subject_rows: u64,
    pub terminal_rows: u64,
    pub retained_analysis_findings: u64,
    pub omitted_analysis_findings: u64,
    pub finding_reached_rows: u64,
    pub finding_candidates: u64,
    pub finding_witness_expansions: u64,
    pub finding_witness_bytes: u64,
    pub solver: SolverWork,
    pub semantic: SemanticBudgetReplay,
    pub materialized_files: u64,
    pub traversal_steps: u64,
    pub artifact_leases: u64,
    pub artifact_lease_bytes: u64,
}

/// What one seed file's execution of one selector contributed to a compile.
///
/// Two halves, because a selector unit answers two questions. `rows` is the
/// query's own product, exactly as a match unit publishes it: the merge sums
/// its counters and checks them against the cumulative caps the whole
/// execution enforces, which is what licenses claiming the merged product is
/// the whole product. `sites` is what the compile actually consumes -- the
/// sites this seed file selected, projected onto content-addressed identities
/// -- because a selected site is derived from a row's own typed value and that
/// value is not reconstructible from the row projection.
///
/// The three charges are what this unit took out of the session's shared
/// semantic ledgers, so a run that reuses the unit leaves those ledgers where
/// the execution left them and the compile's remaining budget after the last
/// unit is the budget a whole-workspace selector execution would have left.
/// There is no artifact charge: a unit whose execution retained artifact
/// allocations is never published, because those allocations are process-local
/// and a reused unit could not hand them to the compile.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorProduct {
    pub rows: UnitExecutionResult,
    pub sites: Vec<SelectorProductSite>,
    pub semantic: SemanticBudgetReplay,
    pub materialized_files: u64,
    pub traversal_steps: u64,
}

impl SelectorProduct {
    /// Incompatible retained selector JSON must trigger fresh execution.
    fn decode_retained(json: &str) -> Option<Box<Self>> {
        serde_json::from_str(json).ok()
    }
}

/// One selected site, over identities a second checkout resolves the same way.
///
/// The workspace-relative path rather than the `ProjectFile` the compile holds
/// (that one carries a checkout root), and the two quality verdicts spelled as
/// their reasons: absent means the verdict was `Proven` or `Complete`, present
/// means it was not and carries why.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorProductSite {
    pub rel_path: Box<str>,
    pub start: usize,
    pub end: usize,
    pub unproven: Option<Box<str>>,
    pub partial: Option<Box<str>>,
}

/// Read one root unit's product back under the budget its projections' caps
/// are stated in.
///
/// A seed for the reason [`AssertFileProductSeed`] is one: a projection is
/// normalized against a budget, and the budget that matters is the reading
/// run's.
pub(crate) struct RootProductSeed<'a> {
    budget: &'a PolicyBudget,
}

impl<'a> RootProductSeed<'a> {
    pub(crate) const fn new(budget: &'a PolicyBudget) -> Self {
        Self { budget }
    }
}

/// The field names a root unit product carries, named once so the visitor and
/// the error it raises for an unknown field cannot disagree.
const ROOT_FIELDS: &[&str] = &["findings", "gaps", "work"];

impl<'de> DeserializeSeed<'de> for RootProductSeed<'_> {
    type Value = RootProduct;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "RootProduct",
            ROOT_FIELDS,
            RootProductVisitor {
                budget: self.budget,
            },
        )
    }
}

/// Reads a root unit product's fields, handing the budget to the projections.
///
/// Hand-written rather than derived for the same reason the assert unit's
/// visitor is: a derived struct cannot carry a seed into one of its fields.
struct RootProductVisitor<'a> {
    budget: &'a PolicyBudget,
}

impl<'de> Visitor<'de> for RootProductVisitor<'_> {
    type Value = RootProduct;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one typestate root's evaluation product")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut findings: Option<Vec<TypestateProjectedFinding>> = None;
        let mut gaps: Option<Vec<TypestateGap>> = None;
        let mut work: Option<RootWork> = None;
        while let Some(field) = map.next_key::<String>()? {
            let duplicate = match field.as_str() {
                "findings" => findings
                    .replace(map.next_value_seed(ProjectionListSeed {
                        budget: self.budget,
                    })?)
                    .is_some(),
                "gaps" => gaps.replace(map.next_value()?).is_some(),
                "work" => work.replace(map.next_value()?).is_some(),
                other => return Err(de::Error::unknown_field(other, ROOT_FIELDS)),
            };
            if duplicate {
                return Err(de::Error::duplicate_field("a root unit product field"));
            }
        }
        let product = RootProduct {
            findings: findings.ok_or_else(|| de::Error::missing_field("findings"))?,
            gaps: gaps.ok_or_else(|| de::Error::missing_field("gaps"))?,
            work: work.ok_or_else(|| de::Error::missing_field("work"))?,
        };
        // One retained analysis finding projects to at least one violation and
        // may project to several -- a terminal expectation with two states
        // outside it is two -- so the counter is bounded by the list rather
        // than equal to it, and neither can be nonzero without the other. A
        // stored product outside those bounds would merge a work report no
        // evaluation produced.
        let projected = u64::try_from(product.findings.len()).unwrap_or(u64::MAX);
        if product.work.retained_analysis_findings > projected
            || (product.work.retained_analysis_findings == 0) != (projected == 0)
        {
            return Err(de::Error::custom(
                "a stored root unit counts retained findings its own projections cannot account \
                 for",
            ));
        }
        Ok(product)
    }
}

/// One root's projections, each read under the reading run's budget.
struct ProjectionListSeed<'a> {
    budget: &'a PolicyBudget,
}

fn collect_seeded_sequence<'de, A, S>(
    mut sequence: A,
    mut seed: impl FnMut() -> S,
) -> Result<Vec<S::Value>, A::Error>
where
    A: SeqAccess<'de>,
    S: DeserializeSeed<'de>,
{
    let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default());
    while let Some(value) = sequence.next_element_seed(seed())? {
        values.push(value);
    }
    Ok(values)
}

impl<'de> DeserializeSeed<'de> for ProjectionListSeed<'_> {
    type Value = Vec<TypestateProjectedFinding>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ProjectionListSeed<'_> {
    type Value = Vec<TypestateProjectedFinding>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list of projected typestate violations")
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        collect_seeded_sequence(seq, || TypestateProjectedFindingSeed::new(self.budget))
    }
}

/// Read one assert unit's product back under the budget its findings' caps are
/// stated in.
///
/// A seed rather than a plain `Deserialize` for the reason
/// [`PolicyFindingSeed`] is one: a finding is validated against a budget, and
/// the budget that matters is the reading run's.
pub(crate) struct AssertFileProductSeed<'a> {
    budget: &'a PolicyBudget,
}

impl<'a> AssertFileProductSeed<'a> {
    pub(crate) const fn new(budget: &'a PolicyBudget) -> Self {
        Self { budget }
    }
}

impl<'de> DeserializeSeed<'de> for AssertFileProductSeed<'_> {
    type Value = AssertFileProduct;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "AssertFileProduct",
            FIELDS,
            AssertFileProductVisitor {
                budget: self.budget,
            },
        )
    }
}

/// Reads the product's fields, handing the budget to the findings.
///
/// Hand-written rather than derived because a derived struct cannot carry a
/// seed into one of its fields, and the findings are exactly the field that
/// needs one.
struct AssertFileProductVisitor<'a> {
    budget: &'a PolicyBudget,
}

impl<'de> Visitor<'de> for AssertFileProductVisitor<'_> {
    type Value = AssertFileProduct;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one assertion file's evaluation product")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut findings: Option<Vec<PolicyFinding>> = None;
        let mut unconcluded: Option<Vec<PolicyIncompleteReason>> = None;
        let mut row_completions: Option<Vec<CodeQueryCompletion>> = None;
        let mut diagnostics: Option<Vec<CodeQueryDiagnostic>> = None;
        let mut work: Option<CodeQueryExecutionWork> = None;
        while let Some(field) = map.next_key::<String>()? {
            let duplicate = match field.as_str() {
                "findings" => findings
                    .replace(map.next_value_seed(FindingListSeed {
                        budget: self.budget,
                    })?)
                    .is_some(),
                "unconcluded" => unconcluded.replace(map.next_value()?).is_some(),
                "row_completions" => row_completions.replace(map.next_value()?).is_some(),
                "diagnostics" => diagnostics.replace(map.next_value()?).is_some(),
                "work" => work.replace(map.next_value()?).is_some(),
                other => return Err(de::Error::unknown_field(other, FIELDS)),
            };
            if duplicate {
                return Err(de::Error::duplicate_field("an assert unit product field"));
            }
        }
        let product = AssertFileProduct {
            findings: findings.ok_or_else(|| de::Error::missing_field("findings"))?,
            unconcluded: unconcluded.ok_or_else(|| de::Error::missing_field("unconcluded"))?,
            row_completions: row_completions
                .ok_or_else(|| de::Error::missing_field("row_completions"))?,
            diagnostics: diagnostics.ok_or_else(|| de::Error::missing_field("diagnostics"))?,
            work: work.ok_or_else(|| de::Error::missing_field("work"))?,
        };
        // A verdict over an incomplete row set is never a pass and never a
        // finding, so a file that could not be concluded contributes none. A
        // stored product that reports both would merge findings the run that
        // produced them had already discarded.
        if !product.findings.is_empty() && !product.unconcluded.is_empty() {
            return Err(de::Error::custom(
                "a stored assert unit reports findings for a file it could not conclude",
            ));
        }
        Ok(product)
    }
}

/// The field names an assert unit product carries, named once so the visitor
/// and the error it raises for an unknown field cannot disagree.
const FIELDS: &[&str] = &[
    "findings",
    "unconcluded",
    "row_completions",
    "diagnostics",
    "work",
];

/// One file's findings, each read under the reading run's budget.
struct FindingListSeed<'a> {
    budget: &'a PolicyBudget,
}

impl<'de> DeserializeSeed<'de> for FindingListSeed<'_> {
    type Value = Vec<PolicyFinding>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for FindingListSeed<'_> {
    type Value = Vec<PolicyFinding>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list of policy findings")
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        collect_seeded_sequence(seq, || PolicyFindingSeed::new(self.budget))
    }
}

/// One published unit: what it answered, and every input that answer depends
/// on.
///
/// `reads` is the ledger's own key set and `read_digest` is derived from it at
/// construction, so the two can never disagree about which reads a unit's
/// verification must cover.
///
/// `snapshots` are the content identities of the workspaces the unit's
/// name-index answers are known to hold on. A name-index read is proved by the
/// names that moved between two workspaces, which holds only for a read set
/// whose index answers are the first workspace's, so a reader verifies a
/// unit's index reads only against what moved since one of these snapshots.
/// The snapshot that computed the unit is one; every later verification adds
/// the snapshots it proved the answers on (see
/// [`PolicyIncrementalContext::publication_snapshots`]).
#[derive(Debug, Clone)]
pub struct PolicyUnit {
    // Buffered publication input, absent on units loaded for reuse/attestation.
    seed_parse_variant: Option<ParseVariant>,
    key: PolicyUnitKey,
    product: PolicyUnitProduct,
    reads: Vec<ReadKey>,
    read_digest: ReadSetDigest,
    budget_mode: BudgetMode,
    snapshots: Vec<StableDigest>,
}

impl PolicyUnit {
    /// Publish one unit's product under the reads that produced it, whose
    /// name-index answers are those of each workspace in `snapshots`.
    pub(crate) fn new(
        key: PolicyUnitKey,
        seed_parse_variant: Option<ParseVariant>,
        product: PolicyUnitProduct,
        reads: Vec<ReadKey>,
        budget_mode: BudgetMode,
        snapshots: Vec<StableDigest>,
    ) -> Self {
        assert!(
            !snapshots.is_empty(),
            "a unit's index answers hold on the snapshot that computed it"
        );
        let read_digest = read_set_digest(&reads);
        Self {
            key,
            seed_parse_variant,
            product,
            reads,
            read_digest,
            budget_mode,
            snapshots,
        }
    }

    pub const fn key(&self) -> &PolicyUnitKey {
        &self.key
    }

    pub(crate) const fn product(&self) -> &PolicyUnitProduct {
        &self.product
    }

    pub fn reads(&self) -> &[ReadKey] {
        &self.reads
    }

    pub const fn read_digest(&self) -> ReadSetDigest {
        self.read_digest
    }

    pub const fn budget_mode(&self) -> BudgetMode {
        self.budget_mode
    }

    /// The content identities of the workspaces this unit's name-index
    /// answers hold on.
    pub fn snapshots(&self) -> &[StableDigest] {
        &self.snapshots
    }

    /// Record that this unit's name-index answers hold on `snapshots` too.
    fn attest(&mut self, snapshots: &[StableDigest]) {
        for snapshot in snapshots {
            if !self.snapshots.contains(snapshot) {
                self.snapshots.push(*snapshot);
            }
        }
    }

    /// Whether any read of this unit is a name-index probe, the one kind of
    /// read whose proof depends on the snapshot that recorded it.
    pub fn reads_name_index(&self) -> bool {
        self.reads
            .iter()
            .any(|read| matches!(read, ReadKey::Index { .. }))
    }
}

/// Where published units are looked up and published.
///
/// One evaluation batch owns one store. Milestone 3 adds the persisted
/// implementation behind the same two operations; nothing above this trait
/// knows which one it is holding.
pub trait PolicyUnitStore: Send {
    /// Load every unit `keys` names, before the lookups start.
    ///
    /// One policy asks about every seed file of the workspace, so a store that
    /// answers each lookup on its own would pay a round trip per file before
    /// reading a single fact. An in-memory store already holds everything and
    /// does nothing here.
    ///
    /// `Err` is a store that could not answer -- a row that would not load,
    /// a database that would not read -- which is not the same as "nothing was
    /// published under this key". A policy whose store failed widens rather
    /// than treating a failure as an absence, because an absence is a claim
    /// about what was published and a failure is a claim about nothing.
    fn prefetch(
        &mut self,
        _keys: &[PolicyUnitKey],
        _budget: &PolicyBudget,
        _row_node_count: Option<usize>,
    ) -> Result<(), PolicyUnitStoreError> {
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit>;
    fn publish(&mut self, unit: PolicyUnit);

    /// Record that the unit under `key`, verified from `verified_on`, holds on
    /// `snapshots` too.
    ///
    /// Applies only while the unit this store holds is still attested on
    /// `verified_on`: verification proved its answers there equal its answers
    /// on `snapshots`, and says nothing about a unit holding other answers.
    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    );
}

/// A store that could not answer.
///
/// Carried as prose because every one of these is reported and none is
/// recovered from: the policy widens, evaluates in full, and says the product
/// could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUnitStoreError(String);

impl PolicyUnitStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for PolicyUnitStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The units one batch published, for the lifetime of that batch.
#[derive(Debug, Default)]
pub struct InMemoryPolicyUnitStore {
    units: HashMap<PolicyUnitKey, PolicyUnit>,
}

impl InMemoryPolicyUnitStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PolicyUnitStore for InMemoryPolicyUnitStore {
    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.units.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.units.insert(unit.key.clone(), unit);
    }

    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    ) {
        if let Some(unit) = self.units.get_mut(key)
            && unit.snapshots.contains(&verified_on)
        {
            unit.attest(snapshots);
        }
    }
}

/// The units of one batch, backed by the repository's analyzer cache.
///
/// Everything a run derives from content lives in that cache, and a unit is
/// derived from content: the file it covers, the files and lookups it read,
/// the policy text, the configuration, the models, the epoch. Publishing units
/// there is what makes the second run of `--diff-base` on the same branch do
/// almost no work, and it is why this exists at all -- an in-memory store
/// serves one process and forgets.
///
/// Reads are prefetched per policy in one query and publications are buffered
/// until the caller flushes them. The incremental context commits a complete
/// policy attempt to this store before buffering, so a widened attempt never
/// leaves a half-published unit set behind; the buffered rows are then written
/// in one database transaction.
pub struct PersistedPolicyUnitStore {
    store: Arc<AnalyzerStore>,
    loaded: HashMap<PolicyUnitKey, PolicyUnit>,
    pending: Vec<PolicyUnit>,
    attestations: Vec<PolicyUnitAttestation>,
    published: usize,
}

impl PersistedPolicyUnitStore {
    pub fn new(store: Arc<AnalyzerStore>) -> Self {
        Self {
            store,
            loaded: HashMap::new(),
            pending: Vec::new(),
            attestations: Vec::new(),
            published: 0,
        }
    }

    /// Write every buffered publication, in one transaction, and then every
    /// buffered attestation.
    ///
    /// The caller decides when: a cancelled or deadline-terminated run flushes
    /// nothing, because its units describe work that stopped early and nothing
    /// downstream can tell that from work that finished. Returns how many
    /// units were published.
    pub fn flush(&mut self) -> Result<usize, PolicyUnitStoreError> {
        let written = self.flush_units()?;
        // After the units, so that a unit this run published and a later
        // policy of the same run verified on another snapshot is in the store
        // when its attestation names it.
        let attestations = std::mem::take(&mut self.attestations);
        self.store
            .attest_policy_units(attestations)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        Ok(written)
    }

    fn flush_units(&mut self) -> Result<usize, PolicyUnitStoreError> {
        if self.pending.is_empty() {
            return Ok(0);
        }
        let rows = self
            .pending
            .drain(..)
            .map(|unit| unit_row(&unit))
            .collect::<Result<Vec<_>, _>>()?;
        let written = self
            .store
            .publish_policy_units(rows)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        self.published += written;
        Ok(written)
    }

    /// How many units this store has written.
    pub const fn published(&self) -> usize {
        self.published
    }

    /// The store these units are published to and read from.
    pub const fn store(&self) -> &Arc<AnalyzerStore> {
        &self.store
    }
}

impl PolicyUnitStore for PersistedPolicyUnitStore {
    fn prefetch(
        &mut self,
        keys: &[PolicyUnitKey],
        budget: &PolicyBudget,
        row_node_count: Option<usize>,
    ) -> Result<(), PolicyUnitStoreError> {
        let wanted = keys
            .iter()
            .filter(|key| !self.loaded.contains_key(key))
            .cloned()
            .collect::<Vec<_>>();
        if wanted.is_empty() {
            return Ok(());
        }
        let rows = wanted.iter().map(row_key).collect::<Vec<_>>();
        let answers = self
            .store
            .policy_units_for_keys(&rows)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        for (key, answer) in wanted.into_iter().zip(answers) {
            let Some(row) = answer else {
                continue;
            };
            // Selector shapes evolve with the policy substrate (#10985). A
            // retained incompatible JSON product is a miss, so execution can
            // rebuild it rather than turn a cache upgrade into a store error.
            let product = if row.product_kind == "selector" {
                let Some(product) = SelectorProduct::decode_retained(&row.product) else {
                    continue;
                };
                PolicyUnitProduct::Selector(product)
            } else {
                product_of_row(&row, budget)?
            };
            self.loaded.insert(
                key.clone(),
                unit_of_row_with_product(key, row, product, row_node_count)?,
            );
        }
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.loaded.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.loaded.insert(unit.key.clone(), unit.clone());
        self.pending.push(unit);
    }

    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    ) {
        let Some(unit) = self.loaded.get_mut(key) else {
            return;
        };
        if !unit.snapshots.contains(&verified_on) {
            return;
        }
        unit.attest(snapshots);
        self.attestations.push(PolicyUnitAttestation {
            key: row_key(key),
            read_set_digest: *unit.read_digest.digest().as_bytes(),
            verified_on: *verified_on.as_bytes(),
            snapshots: snapshots
                .iter()
                .map(|snapshot| *snapshot.as_bytes())
                .collect(),
        });
    }
}

/// The store's spelling of one unit key.
///
/// Digests become lowercase hex and the family becomes its stable label,
/// because a persisted key is compared by SQL and must be one shape per value.
pub fn row_key(key: &PolicyUnitKey) -> PolicyUnitRowKey {
    PolicyUnitRowKey {
        policy_semantic_hash: StableDigest::from_array(*key.policy.as_bytes()).to_string(),
        family: key.family.label().to_string(),
        partition: match &key.partition {
            UnitPartition::Seed {
                language,
                rel_path,
                blob,
            } => PolicyUnitPartitionRow::Seed {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
            },
            UnitPartition::Binding {
                binding,
                language,
                rel_path,
                blob,
            } => PolicyUnitPartitionRow::Binding {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                // The name is digested rather than stored: the persisted
                // column is one shape for every partition that carries one,
                // and nothing reads a binding's name back out of the store --
                // the key a lookup asks with carries it.
                binding: StableDigest::sha256(binding.as_ref()).to_string(),
            },
            UnitPartition::AssertFile {
                language,
                rel_path,
                blob,
                subjects,
            } => PolicyUnitPartitionRow::AssertFile {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                subjects: subjects.to_string(),
            },
            UnitPartition::Root {
                language,
                rel_path,
                blob,
                locator,
                compilation,
            } => PolicyUnitPartitionRow::Root {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                locator: locator.to_string(),
                compilation: compilation.to_string(),
            },
            UnitPartition::Selector {
                language,
                rel_path,
                blob,
                selector,
            } => PolicyUnitPartitionRow::Selector {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                selector: selector.to_string(),
            },
            UnitPartition::Prefix {
                language,
                rel_path,
                blob,
                cut,
                input,
            } => PolicyUnitPartitionRow::Prefix {
                language: *language,
                rel_path: rel_path.to_string(),
                blob: *blob,
                cut: cut.to_string(),
                input: input.to_string(),
            },
            UnitPartition::Output {
                language,
                rel_path,
                blob,
                anchor,
                compilation,
            } => PolicyUnitPartitionRow::Output {
                language: *language,
                rel_path: rel_path.to_string(),
                blob: *blob,
                anchor: anchor.to_string(),
                compilation: compilation.to_string(),
            },
            UnitPartition::Whole => PolicyUnitPartitionRow::Whole,
        },
        configuration_fingerprint: key.configuration.to_string(),
        active_model_set_hash: key.models.to_string(),
        engine_epoch: key.epoch.to_string(),
    }
}

/// One unit as the row the store writes.
fn unit_row(unit: &PolicyUnit) -> Result<PolicyUnitRow, PolicyUnitStoreError> {
    assert_eq!(
        unit.budget_mode,
        BudgetMode::Exhaustive,
        "only an exhaustive unit is publishable, and the schema says so too"
    );
    let product = match &unit.product {
        PolicyUnitProduct::Rows(rows) => serde_json::to_string(rows),
        PolicyUnitProduct::AssertFile(product) => serde_json::to_string(product),
        PolicyUnitProduct::Root(product) => serde_json::to_string(product),
        PolicyUnitProduct::Selector(product) => serde_json::to_string(product),
        PolicyUnitProduct::Prefix(product) => Ok(product.clone()),
        PolicyUnitProduct::Output(product) => Ok(product.clone()),
    }
    .map_err(|error| {
        PolicyUnitStoreError::new(format!("a unit product could not be serialized: {error}"))
    })?;
    Ok(PolicyUnitRow {
        seed_parse_variant: unit.seed_parse_variant,
        key: row_key(&unit.key),
        product_kind: unit.product.stable_label().to_string(),
        product,
        read_set_digest: *unit.read_digest.digest().as_bytes(),
        reads: unit.reads.clone(),
        snapshots: unit
            .snapshots
            .iter()
            .map(|snapshot| *snapshot.as_bytes())
            .collect(),
    })
}

/// The product one stored row carries.
///
/// Reusing a unit against a workspace also needs its read set, which is what
/// [`unit_of_row`] adds around this. `budget` is the reading run's, because an
/// assert unit's product carries findings and a finding's caps are stated in a
/// budget: a product stored under a wider budget than this run allows is a load
/// error rather than a finding this run would never have retained.
fn product_of_row(
    row: &PolicyUnitRow,
    budget: &PolicyBudget,
) -> Result<PolicyUnitProduct, PolicyUnitStoreError> {
    let product = match row.product_kind.as_str() {
        "rows" => serde_json::from_str(&row.product).map(PolicyUnitProduct::Rows),
        "assert_file" => {
            let mut deserializer = serde_json::Deserializer::from_str(&row.product);
            AssertFileProductSeed::new(budget)
                .deserialize(&mut deserializer)
                .map(PolicyUnitProduct::AssertFile)
        }
        "root" => {
            let mut deserializer = serde_json::Deserializer::from_str(&row.product);
            RootProductSeed::new(budget)
                .deserialize(&mut deserializer)
                .map(PolicyUnitProduct::Root)
        }
        "selector" => serde_json::from_str(&row.product).map(PolicyUnitProduct::Selector),
        "prefix" => return Ok(PolicyUnitProduct::Prefix(row.product.clone())),
        "output" => return Ok(PolicyUnitProduct::Output(row.product.clone())),
        other => {
            return Err(PolicyUnitStoreError::new(format!(
                "a published unit carries an unknown product kind `{other}`"
            )));
        }
    };
    product.map_err(|error| {
        PolicyUnitStoreError::new(format!(
            "a published unit product could not be read: {error}"
        ))
    })
}

/// One stored row as the unit an evaluation may reuse.
///
/// Every failure here is a load error rather than a malformed unit: a product
/// that will not parse, a read set whose digest does not match the reads that
/// came back with it. The caller widens and says so; nothing partially loaded
/// ever reaches a merge.
pub fn unit_of_row(
    key: PolicyUnitKey,
    row: PolicyUnitRow,
    budget: &PolicyBudget,
    row_node_count: Option<usize>,
) -> Result<PolicyUnit, PolicyUnitStoreError> {
    let product = product_of_row(&row, budget)?;
    unit_of_row_with_product(key, row, product, row_node_count)
}

fn unit_of_row_with_product(
    key: PolicyUnitKey,
    row: PolicyUnitRow,
    product: PolicyUnitProduct,
    row_node_count: Option<usize>,
) -> Result<PolicyUnit, PolicyUnitStoreError> {
    if let PolicyUnitProduct::Rows(rows) = &product
        && !rows.budgeted_work.step_outputs.is_empty()
        && Some(rows.budgeted_work.step_outputs.len()) != row_node_count
    {
        return Err(PolicyUnitStoreError::new(
            "a published unit's step output counters do not match its physical plan".to_string(),
        ));
    }

    let unit = PolicyUnit::new(
        key,
        None,
        product,
        row.reads,
        BudgetMode::Exhaustive,
        row.snapshots
            .into_iter()
            .map(StableDigest::from_array)
            .collect(),
    );
    if unit.read_digest.digest().as_bytes() != &row.read_set_digest {
        return Err(PolicyUnitStoreError::new(
            "a published unit's read set does not digest to the identity it was published under"
                .to_string(),
        ));
    }
    Ok(unit)
}

/// The three non-source inputs every unit key and every verification carries.
///
/// Read once per evaluated workspace, because all three are properties of the
/// engine, the analyzer and the run's model activation rather than of any one
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceUnitInputs {
    model_read_digest: StableDigest,
    configuration: StableDigest,
    models: StableDigest,
    epoch: StableDigest,
}

impl WorkspaceUnitInputs {
    #[cfg(test)]
    pub(crate) fn with_lowering_identity(mut self, lowering: StableDigest) -> Self {
        self.epoch = policy_substrate_epoch(lowering);
        self
    }
    #[cfg(test)]
    pub(crate) fn with_epoch_before_8837(
        mut self,
        workspace: &WorkspaceAnalyzer,
        models: Option<&ActiveSemanticModelSnapshot>,
    ) -> Self {
        self.epoch = substrate_epoch_before_8837(workspace.policy_lowering_identity(models));
        self
    }

    /// The inputs `workspace` evaluates under, with `models` as the activation
    /// the run pinned.
    ///
    /// The configuration fingerprint is the one the analyzer folds into every
    /// content identity, spelled the same way (#2529): the `Debug` rendering
    /// of the configuration, with a workspace that carries none behaving as
    /// the defaults describe.
    ///
    /// `typos` is the run's identifier typo table. It is pack data activated
    /// for the run, like the models, so its digest joins the `models` digest
    /// and a different table re-runs every unit (#10386). A table changes only
    /// with a rules pack release, which changes other pack content too.
    pub fn of(
        workspace: &WorkspaceAnalyzer,
        models: Option<&ActiveSemanticModelSnapshot>,
        typos: Option<&IdentifierTypoTable>,
    ) -> Self {
        let configuration = workspace.config().cloned().unwrap_or_default();
        let model_set = models.map_or_else(
            || StableDigest::sha256(NO_ACTIVE_MODELS),
            |models| StableDigest::sha256(models.active_models().active_model_set_hash()),
        );
        Self {
            model_read_digest:
                brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
                    models.map(|models| models.active_models().active_model_set_hash()),
                ),
            configuration: StableDigest::sha256(format!("{configuration:?}")),
            models: match typos {
                None => model_set,
                Some(typos) => {
                    let mut bytes = model_set.as_bytes().to_vec();
                    bytes.extend_from_slice(b"\x01identifier-typos\x01");
                    bytes.extend_from_slice(&typos.content_digest());
                    StableDigest::sha256(bytes)
                }
            },
            epoch: policy_substrate_epoch(workspace.policy_lowering_identity(models)),
        }
    }

    pub const fn configuration(&self) -> StableDigest {
        self.configuration
    }

    pub const fn models(&self) -> StableDigest {
        self.models
    }

    pub const fn epoch(&self) -> StableDigest {
        self.epoch
    }

    /// The unit key one policy's `partition` is published under.
    pub fn unit_key(&self, policy: &LoadedPolicy, partition: UnitPartition) -> PolicyUnitKey {
        PolicyUnitKey {
            policy: policy.semantic_hash(),
            family: policy.definition().analysis.analysis_type(),
            partition,
            configuration: self.configuration,
            models: self.models,
            epoch: self.epoch,
        }
    }

    /// What verification compares one policy's recorded reads against.
    pub fn head_inputs(&self, policy: &LoadedPolicy) -> HeadInputs {
        HeadInputs {
            models: self.model_read_digest,
            policy_semantic_hash: StableDigest::from_array(*policy.semantic_hash().as_bytes()),
            policy_source: StableDigest::from_array(*policy.source_hash().as_bytes()),
            configuration: self.configuration,
            epoch: self.epoch,
        }
    }
}

/// The content identity of one analyzed workspace snapshot, as a unit records
/// the workspace that computed it.
///
/// The whole-workspace content identity folds every analyzed path with the
/// blob it resolves to, every overlay, the per-language analysis epochs and
/// the analyzer configuration, and carries no absolute path. Two snapshots
/// with one identity therefore publish the same facts to every name index,
/// which is the property a unit's index reads depend on. `None` when the
/// analyzer states no identity, and such a workspace cannot publish or reuse a
/// unit at all.
pub fn workspace_snapshot(workspace: &WorkspaceAnalyzer) -> Option<StableDigest> {
    workspace
        .analyzer()
        .workspace_content_identities()?
        .whole_workspace()
        .map(|identity| StableDigest::from_array(*identity.as_bytes()))
}

/// The two snapshots a comparison is between.
///
/// A unit computed on either one can be verified here: one computed on `base`
/// against what moved between the base and the head, and one computed on
/// `head` against the head itself. A unit computed on any other snapshot has
/// read index answers this comparison says nothing about, and is recomputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitSnapshots {
    /// The workspace the head is compared against.
    pub base: StableDigest,
    /// The workspace this evaluation runs on. Every unit it publishes carries
    /// this identity.
    pub head: StableDigest,
}

impl UnitSnapshots {
    /// A comparison of one snapshot with itself: a full scan, or the base
    /// half of a diff run. It verifies units computed on that snapshot.
    pub const fn of(snapshot: StableDigest) -> Self {
        Self {
            base: snapshot,
            head: snapshot,
        }
    }
}

/// The units one policy's attempt recomputed, provisional until the attempt
/// ends.
///
/// A sliced attempt can widen after recomputing one or more units; those
/// products must not become visible to later runs. The attempt owns this
/// value, and it leaves only by value: `commit_units` publishes all of it with
/// the policy's unit list, `commit_publishable_units` publishes it without
/// one, and dropping it discards it. A widened or failed attempt therefore
/// cannot leak a provisional product into a later attempt.
#[derive(Debug, Default)]
pub(crate) struct StagedUnits {
    units: HashMap<PolicyUnitKey, PolicyUnit>,
}

impl StagedUnits {
    pub(crate) fn stage(&mut self, unit: PolicyUnit) {
        assert!(
            self.units.insert(unit.key.clone(), unit).is_none(),
            "one policy attempt cannot recompute the same unit key twice"
        );
    }

    pub(crate) fn get(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.units.get(key)
    }
}

/// Everything one evaluation needs to reuse units instead of recomputing them.
///
/// Its presence is the whole condition: an evaluation that holds one has a
/// store to look units up in and a workspace to verify them against, and one
/// that does not executes exactly as it always has. There is no mode to set.
///
/// A full scan and the base half of a `--diff-base` run hold one too. Their
/// changed facts are the workspace against itself, which states that nothing
/// moved, so a unit computed on this same snapshot -- by an earlier scan of
/// this tree, or an earlier evaluation of this base -- has its name-index
/// reads proved by that empty set and every other read checked against the
/// workspace itself. A unit without name-index reads is verified wherever it
/// came from, and one with them from another snapshot is recomputed.
pub struct PolicyIncrementalContext<'a> {
    store: &'a Mutex<dyn PolicyUnitStore>,
    workspace: &'a WorkspaceAnalyzer,
    changed: &'a ChangedFacts,
    /// What moved between the head and itself, built from `changed` the first
    /// time a unit computed on the head asks. Unused when the two snapshots
    /// are one, because `changed` already says exactly that.
    head_unchanged: OnceLock<ChangedFacts>,
    snapshots: UnitSnapshots,
    inputs: WorkspaceUnitInputs,
    base: IncrementalBaseState,
    verdicts: ArtifactVerdictLog,
    runs: Mutex<Vec<PolicyIncrementalRun>>,
    unit_metrics: Mutex<HashMap<PolicyId, UnitPhaseMetrics>>,
    composition_searches: Mutex<HashMap<PolicyId, CompositionSearchMetrics>>,
    discarded_source_inventories:
        Mutex<HashMap<PolicyId, crate::finding::DiscardedSourceInventory>>,
    units: Mutex<Vec<(PolicyId, Vec<PolicyUnitKey>)>>,
    /// Workspace-total base widening can predict that slicing the head will
    /// widen too, so those policies can use their reference whole execution.
    base_workspace_widens: HashMap<PolicyId, WidenReason>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UnitPhaseMetrics {
    pub(crate) prefetch: Duration,
    pub(crate) verify: Duration,
    pub(crate) lookup_replay: Duration,
    pub(crate) recompute: Duration,
    pub(crate) lookups_replayed: u64,
}

/// Observations of composition searches; never used for evaluation.
///
/// A search that ended in an error, or whose provider recorded a failure,
/// counts in `searches_errored` (and `zero_compiled_errored`) and in none of
/// the finding or incompleteness counts: an errored search is not a complete
/// empty search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CompositionSearchMetrics {
    pub searches_total: u64,
    pub searches_errored: u64,
    pub zero_compiled_sources: u64,
    pub zero_compiled_errored: u64,
    pub zero_compiled_with_frontier_sources: u64,
    pub zero_compiled_with_findings: u64,
    pub zero_compiled_incomplete: u64,
    pub frontier_bound_sources: u64,
}

impl CompositionSearchMetrics {
    fn is_empty(&self) -> bool {
        self.searches_total == 0
    }
}

impl<'a> PolicyIncrementalContext<'a> {
    pub fn new(
        store: &'a Mutex<dyn PolicyUnitStore>,
        workspace: &'a WorkspaceAnalyzer,
        changed: &'a ChangedFacts,
        inputs: WorkspaceUnitInputs,
        base: IncrementalBaseState,
        snapshots: UnitSnapshots,
    ) -> Self {
        debug_assert_eq!(
            workspace_snapshot(workspace),
            Some(snapshots.head),
            "a context publishes under the identity of the workspace it evaluates"
        );
        Self {
            store,
            workspace,
            changed,
            head_unchanged: OnceLock::new(),
            snapshots,
            inputs,
            base,
            verdicts: ArtifactVerdictLog::default(),
            runs: Mutex::new(Vec::new()),
            unit_metrics: Mutex::new(HashMap::new()),
            composition_searches: Mutex::new(HashMap::new()),
            discarded_source_inventories: Mutex::new(HashMap::new()),
            units: Mutex::new(Vec::new()),
            base_workspace_widens: HashMap::new(),
        }
    }

    /// Carry only workspace-total widening from a base evaluated in this run.
    /// These two reasons depend on workspace totals, which base and head share
    /// up to the change; plan-only reasons fire before enumeration, while
    /// unit-content reasons can differ between base and head.
    ///
    /// This is a prediction, not an observation: a head that would have
    /// sliced (the change took it under the cap) is evaluated whole anyway.
    /// Whole evaluation is the reference answer, so a wrong prediction loses
    /// reuse, never correctness.
    pub fn with_base_review(mut self, review: Option<&PolicyIncrementalReview>) -> Self {
        if let Some(review) = review.filter(|review| review.base == IncrementalBaseState::Evaluated)
        {
            self.base_workspace_widens = review
                .policies
                .iter()
                .filter_map(|run| match run.widen_reason {
                    Some(
                        reason @ (WidenReason::MergedLimitReached
                        | WidenReason::VerificationBudgetExceeded),
                    ) => Some((run.policy_id.clone(), reason)),
                    _ => None,
                })
                .collect();
        }
        self
    }

    pub fn base_workspace_widen(&self, policy_id: &PolicyId) -> Option<WidenReason> {
        self.base_workspace_widens.get(policy_id).copied()
    }

    /// The content identity of the workspace this context evaluates.
    pub const fn snapshot(&self) -> StableDigest {
        self.snapshots.head
    }

    /// The snapshots whose name-index answers a unit with `reads` holds, once
    /// this context computed it or verified it.
    ///
    /// The head always: it computed the unit, or verification proved the
    /// unit's answers equal the head's. The base too when none of its index
    /// probes names a name that moved between the base and the head, because
    /// then the head answered every one of them exactly as the base would:
    /// that is what the changed-name set states. Holding both is what serves
    /// both common flows. Several heads checked against one base verify the
    /// unit against their own difference from that base, and a chain of checks,
    /// each based on the previous head, verifies it against the difference
    /// from that head. A unit that probed a moved name holds only on this
    /// head. An incomplete changed-name set proves nothing about the base.
    pub fn publication_snapshots(&self, reads: &[ReadKey]) -> Vec<StableDigest> {
        let base_answers = self.snapshots.base != self.snapshots.head
            && self.changed.is_complete()
            && reads.iter().all(|read| match read {
                ReadKey::Index { family, key } => !self.changed.contains(*family, key),
                _ => true,
            });
        if base_answers {
            vec![self.snapshots.head, self.snapshots.base]
        } else {
            vec![self.snapshots.head]
        }
    }

    /// One snapshot of `unit_snapshots` this comparison is between, with what
    /// moved between it and this context's head, or `None` when the unit holds
    /// on neither.
    ///
    /// Only a name-index read depends on the answer: every other read is
    /// checked against the head itself. A name-index read is proved by the
    /// names that moved since a snapshot it holds on, so a unit that holds on
    /// the head is checked against nothing, one that holds on the base against
    /// what moved between the base and the head, and a unit from anywhere else
    /// cannot be checked at all. The head is preferred because it proves every
    /// index read without looking at any name.
    pub fn changed_since(
        &self,
        unit_snapshots: &[StableDigest],
    ) -> Option<(StableDigest, &ChangedFacts)> {
        if unit_snapshots.contains(&self.snapshots.head) {
            let changed = if self.snapshots.base == self.snapshots.head {
                self.changed
            } else {
                self.head_unchanged.get_or_init(|| self.changed.head_only())
            };
            Some((self.snapshots.head, changed))
        } else if unit_snapshots.contains(&self.snapshots.base) {
            Some((self.snapshots.base, self.changed))
        } else {
            None
        }
    }

    pub const fn store(&self) -> &'a Mutex<dyn PolicyUnitStore> {
        self.store
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub const fn changed(&self) -> &'a ChangedFacts {
        self.changed
    }

    pub const fn inputs(&self) -> WorkspaceUnitInputs {
        self.inputs
    }

    /// The reuse decisions this evaluation reached, in the typed vocabulary
    /// #2449 established.
    pub const fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    /// Record what one policy's evaluation did with its units.
    pub fn record_run(&self, run: PolicyIncrementalRun) {
        self.runs
            .lock()
            .expect("policy incremental runs mutex poisoned")
            .push(run);
    }

    pub(crate) fn record_composition_search(
        &self,
        policy_id: &PolicyId,
        compiled_sources: usize,
        frontier_sources: usize,
        findings: bool,
        incomplete: bool,
        errored: bool,
    ) {
        let mut searches = self
            .composition_searches
            .lock()
            .expect("composition search metrics mutex poisoned");
        let metrics = searches.entry(policy_id.clone()).or_default();
        metrics.searches_total += 1;
        metrics.searches_errored += u64::from(errored);
        metrics.frontier_bound_sources += frontier_sources as u64;
        if compiled_sources == 0 {
            metrics.zero_compiled_sources += 1;
            metrics.zero_compiled_errored += u64::from(errored);
            metrics.zero_compiled_with_frontier_sources += u64::from(frontier_sources != 0);
            metrics.zero_compiled_with_findings += u64::from(findings);
            metrics.zero_compiled_incomplete += u64::from(incomplete);
        }
    }

    pub(crate) fn record_discarded_source_inventory(
        &self,
        policy_id: &PolicyId,
        inventory: crate::finding::DiscardedSourceInventory,
    ) {
        self.discarded_source_inventories
            .lock()
            .expect("discarded inventory mutex poisoned")
            .insert(policy_id.clone(), inventory);
    }

    pub(crate) fn note_discarded_source_frontier(
        &self,
        policy_id: &PolicyId,
        selector: &str,
        file: &str,
        gaps: &[String],
    ) {
        let mut inventories = self
            .discarded_source_inventories
            .lock()
            .expect("discarded inventory mutex poisoned");
        if let Some(inventory) = inventories.get_mut(policy_id) {
            for entry in &mut inventory.lost_attributed {
                if entry.selector == selector && entry.attributed_file.as_deref() == Some(file) {
                    entry.frontier_entered_file = true;
                    entry.file_slice_reported_again |= gaps.contains(&entry.message);
                    brokk_bifrost_analysis::profiling::note_with(|| {
                        format!("taint.inventory.frontier_observation={entry:?}")
                    });
                }
            }
        }
    }

    pub(crate) fn has_run(&self, policy_id: &PolicyId) -> bool {
        self.runs
            .lock()
            .expect("policy incremental runs mutex poisoned")
            .iter()
            .any(|run| &run.policy_id == policy_id)
    }

    /// Add one sliced attempt's phase times and replay count to its policy.
    ///
    /// A policy can run more than one attempt (typestate keeps selector and
    /// root units apart), so the record is a sum.
    pub(crate) fn add_unit_metrics(&self, policy_id: &PolicyId, attempt: UnitPhaseMetrics) {
        let mut metrics = self
            .unit_metrics
            .lock()
            .expect("policy unit metrics mutex poisoned");
        let metrics = metrics.entry(policy_id.clone()).or_default();
        metrics.prefetch += attempt.prefetch;
        metrics.verify += attempt.verify;
        metrics.lookup_replay += attempt.lookup_replay;
        metrics.recompute += attempt.recompute;
        metrics.lookups_replayed += attempt.lookups_replayed;
    }

    pub(crate) fn unit_phase_metrics(&self, policy_id: &PolicyId) -> Option<UnitPhaseMetrics> {
        self.unit_metrics
            .lock()
            .expect("policy unit metrics mutex poisoned")
            .get(policy_id)
            .copied()
    }

    /// Publish every unit one policy's attempt staged, and record the unit
    /// list its product was merged from.
    ///
    /// Recorded only when every one of them is published, because a persisted
    /// evaluation names these as the work behind its findings and a partial
    /// list would name work that no policy did.
    pub(crate) fn commit_units(
        &self,
        policy_id: PolicyId,
        mut staged: StagedUnits,
        keys: Vec<PolicyUnitKey>,
    ) {
        let mut seen = HashSet::with_capacity(keys.len());
        let mut committed = Vec::with_capacity(staged.units.len());
        for key in &keys {
            assert!(
                seen.insert(key),
                "a complete unit-key set cannot contain duplicate keys"
            );
            if let Some(unit) = staged.units.remove(key) {
                committed.push(unit);
            }
        }
        assert!(
            staged.units.is_empty(),
            "every recomputed unit must be included in the complete unit-key set"
        );
        {
            let mut store = self.store.lock().expect("policy-unit store mutex poisoned");
            for unit in committed {
                store.publish(unit);
            }
        }
        self.units
            .lock()
            .expect("policy incremental units mutex poisoned")
            .push((policy_id, keys));
    }

    /// Publish the units one policy's attempt staged, without recording a unit
    /// list.
    ///
    /// A staged unit has a bounded ledger, is not execution dependent and is
    /// not budget stopped, so it is valid on its own: reuse finds it by key and
    /// checks its own read set. The recorded list only pins units against the
    /// age sweep, and `commit_units` keeps it for a fully published policy.
    /// Units publish in `seed_order`, so the store sees a stable order. This is for a sliced Output attempt that finished every unit but
    /// refused some, so the refused siblings do not discard the good ones
    /// (#9947).
    pub(crate) fn commit_publishable_units(
        &self,
        mut staged: StagedUnits,
        seed_order: &[PolicyUnitKey],
    ) {
        let mut store = self.store.lock().expect("policy-unit store mutex poisoned");
        for key in seed_order {
            if let Some(unit) = staged.units.remove(key) {
                store.publish(unit);
            }
        }
        assert!(
            staged.units.is_empty(),
            "every staged unit belongs to the attempt's seed order"
        );
    }

    /// The units each policy's product was merged from, in policy order.
    pub fn published_units(&self) -> Vec<(PolicyId, Vec<PolicyUnitKey>)> {
        self.units
            .lock()
            .expect("policy incremental units mutex poisoned")
            .clone()
    }

    /// The review of everything this evaluation reused, in policy order.
    pub fn review(&self) -> PolicyIncrementalReview {
        // The replay count is joined here rather than when a run is recorded:
        // a sliced attempt reports its metrics when its reuse state drops,
        // which can be after the policy recorded its run.
        let metrics = self
            .unit_metrics
            .lock()
            .expect("policy unit metrics mutex poisoned");
        let searches = self
            .composition_searches
            .lock()
            .expect("composition search metrics mutex poisoned");
        let inventories = self
            .discarded_source_inventories
            .lock()
            .expect("discarded inventory mutex poisoned");
        let policies = self
            .runs
            .lock()
            .expect("policy incremental runs mutex poisoned")
            .iter()
            .map(|run| PolicyIncrementalRun {
                lookups_replayed: metrics
                    .get(&run.policy_id)
                    .map_or(0, |metrics| metrics.lookups_replayed),
                composition_searches: searches.get(&run.policy_id).copied().unwrap_or_default(),
                discarded_source_inventory: inventories.get(&run.policy_id).cloned().map(Box::new),
                ..run.clone()
            })
            .collect();
        PolicyIncrementalReview {
            base: self.base,
            policies,
        }
    }
}

/// How this run obtained the base revision's findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalBaseState {
    /// The base revision was exported, built and evaluated by this run.
    Evaluated,
    /// An earlier run had already evaluated this exact base, so the identities
    /// it concluded were read from the store and the base was neither
    /// exported, built nor evaluated.
    Reused,
}

impl IncrementalBaseState {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Evaluated => "evaluated",
            Self::Reused => "reused",
        }
    }
}

/// Whether one policy was evaluated unit by unit or in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalMode {
    Sliced,
    Full,
}

impl IncrementalMode {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Sliced => "sliced",
            Self::Full => "full",
        }
    }
}

/// Why one policy was evaluated in full instead of unit by unit.
///
/// Widening is always reported. A run that could not bound a unit exactly, or
/// could not merge its units into the bytes a whole evaluation would have
/// produced, evaluates the whole policy and says which of these was true --
/// never silently omits anything, and never claims a reuse it cannot prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenReason {
    /// The family has no per-partition product at all (taint and flow today,
    /// and every family this milestone has not sliced yet).
    WholePolicyFamily,
    /// The plan's rows are not the concatenation of its per-seed rows.
    PlanCrossesSeeds,
    /// The plan needs workspace-wide preparation that is not safely shared
    /// across independent seed units. Evaluate it once before attempting units.
    WorkspacePreparationRequired,
    /// A unit performed reads the ledger could not name.
    UnitUnbounded,
    /// A unit's own execution was truncated or ran under a bounded budget.
    UnitNotExhaustive,
    /// A unit reported a query diagnostic, which is not additive across
    /// partitions.
    UnitDiagnostics,
    /// The merged product reached a cap the whole execution enforces globally,
    /// so the whole execution might have truncated somewhere in its own order.
    MergedLimitReached,
    /// Verifying the recorded reads would have cost more than the evaluation
    /// it is trying to avoid.
    VerificationBudgetExceeded,
    /// The evidence a verification needs does not exist: an incomplete
    /// changed-fact set, a lookup the head cannot answer, or a base
    /// evaluation the run refused to trust and therefore compared nothing
    /// against.
    ReverseDependencyEvidenceMissing,
    /// A published product could not be loaded.
    ProductLoadFailed,
    /// Reuse was turned off for this run (`--no-incremental`, or
    /// `PolicyEvaluationOptions::with_incremental(false)`). Nothing was
    /// looked up and nothing was published; the policy was evaluated exactly
    /// as a run with no units evaluates it.
    IncrementalDisabled,
}

impl WidenReason {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::WholePolicyFamily => "whole_policy_family",
            Self::PlanCrossesSeeds => "plan_crosses_seeds",
            Self::WorkspacePreparationRequired => "workspace_preparation_required",
            Self::UnitUnbounded => "unit_unbounded",
            Self::UnitNotExhaustive => "unit_not_exhaustive",
            Self::UnitDiagnostics => "unit_diagnostics",
            Self::MergedLimitReached => "merged_limit_reached",
            Self::VerificationBudgetExceeded => "verification_budget_exceeded",
            Self::ReverseDependencyEvidenceMissing => "reverse_dependency_evidence_missing",
            Self::ProductLoadFailed => "product_load_failed",
            Self::IncrementalDisabled => "incremental_disabled",
        }
    }
}

/// Why one recomputed Output unit was not published, counted per unit in
/// `PolicyIncrementalRun::output_refusals`. Observational: these labels do
/// not change publication, keys or diagnostics. One unit can have several
/// causes, so the counts overlap and do not sum to the number of refused
/// units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRefusalCause {
    DiagnosticsOpen,
    NotCompleteOrAuthoredProven,
    AttributionRunExhausted,
    OmittedFindings,
    OmittedBarriers,
    UndecidedBarrierChecks,
    IncompleteOrTruncatedFinding,
    IncompleteOrTruncatedWitness,
    PublishableFalse,
    /// `OutputUnitSlice::execution_dependent` was true, so the unit's receipt
    /// was not kept. For Output units that predicate is "report evidence is
    /// incomplete or diagnostics are open", the same test as not publishable;
    /// it does not by itself show that the result depended on budget,
    /// cancellation or other execution state.
    ExecutionDependentReceipt,
    UnusableReceipt,
    InnerEvaluationError,
    ProjectionFailure,
}

/// What one policy's evaluation did with its units.
///
/// The counts describe the sliced attempt even when it widened, because "this
/// policy enumerated forty units and recomputed one before the merge reached a
/// cap" is the diagnosis a reader needs, and a widened policy that reported
/// zeros would hide it.
///
/// The `base_` fields say the same of the base revision's evaluation of this
/// policy in the same run. They are zero when the run evaluated no base -- it
/// served the base from a stored evaluation, or reuse was off -- and a base
/// that reused every unit an earlier scan of that revision published reports
/// them all as reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalRun {
    pub policy_id: PolicyId,
    pub mode: IncrementalMode,
    pub units_total: u64,
    pub units_reused: u64,
    pub units_recomputed: u64,
    pub units_unbounded: u64,
    pub lookups_replayed: u64,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub output_refusals: std::collections::BTreeMap<OutputRefusalCause, u64>,
    #[serde(skip_serializing_if = "CompositionSearchMetrics::is_empty")]
    pub composition_searches: CompositionSearchMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discarded_source_inventory: Option<Box<crate::finding::DiscardedSourceInventory>>,
    /// Why the policy was evaluated whole. With `units_total` zero and a
    /// workspace-total reason (`merged_limit_reached`,
    /// `verification_budget_exceeded`), the head did not attempt units: the
    /// reason was predicted from this run's base evaluation rather than
    /// observed on the head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widen_reason: Option<WidenReason>,
    /// The plan eligibility or merged-limit detail of query-unit widening. Taint selector
    /// fallback details are not currently copied here; only their widening
    /// reason is retained in range diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widen_detail: Option<PlanWidenDetail>,
    pub base_units_reused: u64,
    pub base_units_recomputed: u64,
    pub base_lookups_replayed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_widen_reason: Option<WidenReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_widen_detail: Option<PlanWidenDetail>,
}

impl PolicyIncrementalRun {
    /// One policy whose family has no per-partition product.
    ///
    /// Taint and flow are whole by design: their solve is one batch over
    /// every region at once, and no partition of it has a product. They are
    /// evaluated exactly as a run with no units evaluates them, and say so.
    pub const fn whole_family(policy_id: PolicyId) -> Self {
        Self::evaluated_in_full(policy_id, WidenReason::WholePolicyFamily)
    }

    /// One policy evaluated whole, for `reason`.
    ///
    /// The counts are zero because nothing was enumerated: a policy that
    /// never attempted a sliced evaluation has no units to report, which is a
    /// different statement from a sliced attempt that widened and reports what
    /// it had enumerated when it did.
    pub const fn evaluated_in_full(policy_id: PolicyId, reason: WidenReason) -> Self {
        Self {
            policy_id,
            mode: IncrementalMode::Full,
            units_total: 0,
            units_reused: 0,
            units_recomputed: 0,
            units_unbounded: 0,
            lookups_replayed: 0,
            output_refusals: std::collections::BTreeMap::new(),
            composition_searches: CompositionSearchMetrics {
                searches_total: 0,
                searches_errored: 0,
                zero_compiled_sources: 0,
                zero_compiled_errored: 0,
                zero_compiled_with_frontier_sources: 0,
                zero_compiled_with_findings: 0,
                zero_compiled_incomplete: 0,
                frontier_bound_sources: 0,
            },
            discarded_source_inventory: None,
            widen_reason: Some(reason),
            widen_detail: None,
            base_units_reused: 0,
            base_units_recomputed: 0,
            base_lookups_replayed: 0,
            base_widen_reason: None,
            base_widen_detail: None,
        }
    }

    /// Record what the base evaluation of the same policy did with its units.
    fn with_base(mut self, base: &Self) -> Self {
        assert_eq!(
            self.policy_id, base.policy_id,
            "a base run describes the same policy as the head run it annotates"
        );
        self.base_units_reused = base.units_reused;
        self.base_units_recomputed = base.units_recomputed;
        self.base_lookups_replayed = base.lookups_replayed;
        self.base_widen_reason = base.widen_reason;
        self.base_widen_detail = base.widen_detail;
        self
    }
}

/// What one batch reused, per policy.
///
/// Carried beside the report rather than inside it: Milestone 3 adds the
/// report section, its retained-size accounting and its renderer. Until then
/// this is the structural evidence a test reads to prove that a byte-identical
/// report was produced by doing less work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalReview {
    base: IncrementalBaseState,
    policies: Vec<PolicyIncrementalRun>,
}

/// The three review enums serialize as their stable labels, which are stated
/// once beside the variants rather than a second time in a serde attribute:
/// the label is the wire contract, and a rename that changed one and not the
/// other would ship two spellings of the same state.
impl Serialize for IncrementalBaseState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_stable_label(self.stable_label(), serializer)
    }
}

impl Serialize for IncrementalMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_stable_label(self.stable_label(), serializer)
    }
}

impl Serialize for WidenReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_stable_label(self.stable_label(), serializer)
    }
}

fn serialize_stable_label<S: serde::Serializer>(
    label: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(label)
}

impl PolicyIncrementalReview {
    /// The review of a diff-base run that reused nothing, with `reason` said
    /// once per policy that ran.
    ///
    /// Every `--diff-base` run carries this section, whether or not it reused
    /// anything, because the section is charged to the report's retention
    /// budget: one present in a reusing run and absent in the forced-full run
    /// it must equal byte for byte would move the retention boundary between
    /// them. A run that reused nothing evaluated its base itself, which is
    /// what `Evaluated` says.
    pub fn evaluated_in_full(
        policy_ids: impl IntoIterator<Item = PolicyId>,
        reason: WidenReason,
    ) -> Self {
        Self {
            base: IncrementalBaseState::Evaluated,
            policies: policy_ids
                .into_iter()
                .map(|policy_id| PolicyIncrementalRun::evaluated_in_full(policy_id, reason))
                .collect(),
        }
    }

    pub const fn base(&self) -> IncrementalBaseState {
        self.base
    }

    /// This review with each policy annotated by what the base evaluation of
    /// that policy, in the same run, did with its units.
    ///
    /// A policy the base did not evaluate keeps zero base counts: there was
    /// no base work for it to describe.
    pub fn with_base_runs(self, base: &Self) -> Self {
        let policies = self
            .policies
            .into_iter()
            .map(|run| match base.policy(&run.policy_id) {
                Some(base_run) => run.with_base(base_run),
                None => run,
            })
            .collect();
        Self {
            base: self.base,
            policies,
        }
    }

    pub fn policies(&self) -> &[PolicyIncrementalRun] {
        &self.policies
    }

    /// How many units this batch reused instead of recomputing.
    pub fn reused_units(&self) -> u64 {
        self.policies
            .iter()
            .fold(0, |total, run| total.saturating_add(run.units_reused))
    }

    /// How many units this batch recomputed.
    pub fn recomputed_units(&self) -> u64 {
        self.policies
            .iter()
            .fold(0, |total, run| total.saturating_add(run.units_recomputed))
    }

    /// One policy's run, by identifier.
    pub fn policy(&self, policy_id: &PolicyId) -> Option<&PolicyIncrementalRun> {
        self.policies.iter().find(|run| &run.policy_id == policy_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained::RetainedSize;
    use brokk_bifrost_analysis::analyzer::IndexFamily;
    use brokk_bifrost_analysis::{AnalyzerConfig, FilesystemProject};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn incompatible_retained_selector_json_is_a_miss() {
        // An older shape may have fields the current decoder no longer knows,
        // or lack mandatory fields. Neither is an evaluation failure.
        for json in [r#"{"sites":[],"legacy_rows":[]}"#, r#"{"sites":[]}"#] {
            assert!(SelectorProduct::decode_retained(json).is_none());
        }
    }

    #[test]
    #[hardwon("#9017: retained policy evaluations replayed across a lowering-only adapter bump")]
    fn lowering_identity_rotates_unit_and_head_keys() {
        let registry = crate::test_support::registry_with_policy(
            "test:lowering-epoch",
            r#"(policy :id "test.lowering-epoch" :name "Epoch" :message "Epoch"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language python (class)))))"#,
            "valid key-boundary policy",
        );
        let policy = registry.policies().next().unwrap();
        let lowering = |version: &[u8]| {
            let identity = brokk_bifrost_analysis::analyzer::semantic::service::SemanticAdapterIdentity::for_adapter(
                "python", version, b"python-intrafile-execution-defaults-v1",
                brokk_bifrost_analysis::analyzer::semantic::DependencyFingerprint::hash_bytes(
                    b"no-intrafile-dependencies"),
            );
            brokk_bifrost_analysis::analyzer::workspace::policy_lowering_identity_from_adapters([(
                Language::Python,
                identity,
                None,
            )])
        };
        let fixed = WorkspaceUnitInputs {
            model_read_digest:
                brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(None),
            configuration: StableDigest::sha256("configuration"),
            models: StableDigest::sha256("models"),
            epoch: policy_substrate_epoch(lowering(b"python-value-semantics-v57")),
        };
        let changed = fixed.with_lowering_identity(lowering(b"python-value-semantics-v58"));
        assert_ne!(
            row_key(&fixed.unit_key(policy, UnitPartition::Whole)),
            row_key(&changed.unit_key(policy, UnitPartition::Whole))
        );
        assert_ne!(
            fixed.head_inputs(policy).epoch,
            changed.head_inputs(policy).epoch
        );
        let options = crate::test_support::evaluation_options("2026-07-27");
        let scope = crate::scope::parse_policy_scope_document(
            r#"{"schema_version":1,"scopes":[{"path":"tests","reason":"Acquisitions outside production.","exclude_roots":true}]}"#,
        ).unwrap();
        assert_ne!(
            crate::coordinator::base_evaluation_key(&options, None, fixed).options_digest,
            crate::coordinator::base_evaluation_key(&options, Some(&scope), fixed).options_digest,
            "scoped evaluation rows cannot satisfy unscoped requests",
        );

        assert_ne!(
            crate::coordinator::base_evaluation_key(&options, None, fixed),
            crate::coordinator::base_evaluation_key(&options, None, changed),
        );
        let head_key = |inputs| {
            brokk_bifrost_analysis::analyzer::store::policy_units::PolicyEvaluationRowKey {
                base_tree_oid: "head-tree".to_owned(),
                ..crate::coordinator::base_evaluation_key(&options, None, inputs)
            }
        };
        assert_ne!(head_key(fixed), head_key(changed));
        assert_eq!(
            fixed,
            fixed.with_lowering_identity(lowering(b"python-value-semantics-v57"))
        );
    }

    #[test]
    #[hardwon("#9017: adding the first Python file rotated unchanged policy keys")]
    fn lowering_identity_ignores_workspace_language_presence() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::TypeScript)
            .with_git()
            .file("a.ts", "export function target() {}\n")
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(
                Arc::new(FilesystemProject::new(fixture.root()).expect("project")),
                AnalyzerConfig::default(),
            )
            .expect("workspace")
        };
        let before = build();
        let WorkspaceAnalyzer::Multi(before_multi) = &before else {
            panic!("TypeScript workspace must have delegates");
        };
        assert!(!before_multi.delegates().contains_key(&Language::Python));
        let first = WorkspaceUnitInputs::of(&before, None, None);
        std::fs::write(fixture.root().join("new.py"), "class Added:\n    pass\n")
            .expect("add Python file");
        let after = build();
        let WorkspaceAnalyzer::Multi(after_multi) = &after else {
            panic!("Python workspace must have delegates");
        };
        assert!(after_multi.delegates().contains_key(&Language::Python));
        let second = WorkspaceUnitInputs::of(&after, None, None);
        assert_eq!(
            before.policy_lowering_identity(None),
            after.policy_lowering_identity(None)
        );
        assert_eq!(first, second);
        let registry = crate::test_support::registry_with_policy(
            "test:presence-epoch",
            r#"(policy :id "test.presence-epoch" :name "Epoch" :message "Epoch"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language typescript (class)))))"#,
            "valid key-boundary policy",
        );
        let policy = registry.policies().next().expect("policy");
        assert_eq!(
            row_key(&first.unit_key(policy, UnitPartition::Whole)),
            row_key(&second.unit_key(policy, UnitPartition::Whole))
        );
        let options = crate::test_support::evaluation_options("2026-07-27");
        assert_eq!(
            crate::coordinator::base_evaluation_key(&options, None, first),
            crate::coordinator::base_evaluation_key(&options, None, second)
        );
    }

    #[test]
    fn edited_workspace_keeps_index_proofs_on_the_snapshot_that_answered_them() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::TypeScript)
            .with_git()
            .file("a.ts", "export function target() {}\n")
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(
                Arc::new(FilesystemProject::new(fixture.root()).expect("project")),
                AnalyzerConfig::default(),
            )
            .expect("workspace")
        };
        let base = build();
        let base_snapshot = workspace_snapshot(&base).expect("base identity");
        std::fs::write(fixture.root().join("a.ts"), "export function safe() {}\n")
            .expect("rename declaration");
        let head = build();
        let head_snapshot = workspace_snapshot(&head).expect("head identity");
        assert_ne!(
            base_snapshot, head_snapshot,
            "the edit changes the workspace identity"
        );

        let changed = ChangedFacts::between(&base, &head);
        assert!(
            changed.is_complete(),
            "the fixture needs a complete index difference"
        );
        let family = IndexFamily::DefinitionIdentifier;
        assert!(
            changed.contains(family, b"target"),
            "the renamed name must move"
        );
        assert!(!changed.contains(family, b"other"));
        let store = Mutex::new(InMemoryPolicyUnitStore::new());
        let context = PolicyIncrementalContext::new(
            &store,
            &head,
            &changed,
            WorkspaceUnitInputs::of(&head, None, None),
            IncrementalBaseState::Evaluated,
            UnitSnapshots {
                base: base_snapshot,
                head: head_snapshot,
            },
        );
        assert_eq!(context.snapshot(), head_snapshot);
        assert_eq!(
            context.publication_snapshots(&[ReadKey::index(family, b"target")]),
            vec![head_snapshot],
            "a moved name cannot attest the base answer",
        );
        assert_eq!(
            context.publication_snapshots(&[ReadKey::index(family, b"other")]),
            vec![head_snapshot, base_snapshot],
            "an unchanged name can attest both answers",
        );
        let (verified_on, base_changes) = context
            .changed_since(&[base_snapshot])
            .expect("base-attested unit");
        assert_eq!(verified_on, base_snapshot);
        assert!(base_changes.contains(family, b"target"));
        let (verified_on, head_changes) = context
            .changed_since(&[base_snapshot, head_snapshot])
            .expect("head-attested unit");
        assert_eq!(verified_on, head_snapshot);
        assert!(!head_changes.contains(family, b"target"));

        let registry = crate::test_support::registry_with_policy(
            "test:mixed-reads",
            r#"(policy :id "test.mixed-reads" :name "Mixed reads" :message "Matched"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language typescript (function)))))"#,
            "mixed index and path reads",
        );
        let policy = registry.policies().next().expect("policy");
        let unit = PolicyUnit::new(
            WorkspaceUnitInputs::of(&head, None, None).unit_key(policy, UnitPartition::Whole),
            None,
            PolicyUnitProduct::AssertFile(AssertFileProduct {
                findings: Vec::new(),
                unconcluded: Vec::new(),
                row_completions: Vec::new(),
                diagnostics: Vec::new(),
                work: Default::default(),
            }),
            vec![
                ReadKey::index(family, b"target"),
                ReadKey::path_absent(Language::TypeScript, "missing.ts"),
            ],
            BudgetMode::Exhaustive,
            vec![base_snapshot],
        );
        assert!(
            unit.reads_name_index(),
            "a mixed read set still depends on a name index"
        );
    }

    #[test]
    fn modeled_python_hierarchy_invalidates_units_and_heads_with_unchanged_models() {
        let registry = crate::test_support::registry_with_policy(
            "test:hierarchy-epoch",
            r#"(policy :id "test.hierarchy-epoch" :name "Epoch" :message "Epoch"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language python (class)))))"#,
            "valid key-boundary policy",
        );
        let policy = registry.policies().next().unwrap();
        for component in [
            "-7314-m10a0-per-framework-symbols",
            "-7314-m10a0-named-open-symbols",
            "-10357-file-program-evidence",
            "-10356-derived-sdk-default-compile",
            "-10689-rank-within-language-family",
            "-8837-csharp-configuration-presence",
            "-7619-java-generic-result-receivers",
            // #8388: Go taint admission by caller-inventory capability.
            "-8388-go-composed-taint",
            "-8333-scala-compiler-root-owner",
            "-8513-scaled-retention-budget",
            "-8856-budget-independent-base-replay",
            // Callee heap outputs bind to shared caller storage.
            "-8896-composed-member-call-bindings",
            "-8415-enclosing-type-parameters",
            "-8823-jdk-pack-type-parameter-scope",
            "-8546-model-edit-recomputes-units",
            "-8283-structural-result-type-identity",
            "-7577-scala-cast-expression-types",
            "-8287-merged-limit-partition",
            "-7187-jvm-type-parameter-bindings",
            "-2445-content-cause-precision",
            "-2445-unsupported-member-family-unresolved",
            "-2445-content-partial-diagnostics",
            "-8385-position-free-read-keys",
            "-7886-nested-budget-stop-propagation",
            "-5511-python-modeled-runtime-ancestry",
            "-5721-python-local-import-bases",
            "-5738-intrinsic-root-evidence",
            "-5745-python-runtime-class-binding",
            "-5751-python-class-object-aliases",
            "-5812-iteration-value-origins",
            "5113-returned-refinement-census-v4",
            "-5113-reference-inventory-ownership",
            "-5964-comparison-chain-demand-proof",
            "-7464-csharp-incoming-overload-partition",
            "-7368-7369-csharp-equals-argument-identity",
            "-7289-field-initializer-reads",
            "-7150-go-call-result-counts",
            "-7379-dereference-store-operations",
            "-7344-7345-csharp-compound-writes",
            "-7373-csharp-contextual-keyword-binders",
            "-7371-nonlocal-branch-distinction-7372-initializer-body-relations",
            "-7107-content-diagnostic-units",
            "-rust-deref-receiver-steps-7226",
            "-7219-rust-concrete-receiver-closed",
            "-7150-open-member-calls",
            "-7340-live-region-overwrite-veto",
            "-7520-go-interface-dispatch-references",
            "-analysis-quicksilver-round12-boolean-contexts-binder-spans",
            "-analysis-quicksilver-round12-fact-analyzers",
            "-7471-go-short-var-redeclaration",
            "-7341-7342-go-remainder-comma-ok",
            "-7617-go-direct-type-shapes",
            "-7343-go-static-type-failure-branches",
            "-7393-unproven-nonempty-failure-branches",
            "-7470-go-visible-binding-shapes",
            "-7616-go-modeled-package-result-unknown",
            "-analysis-quicksilver-round12-config-lookup",
            "-7518-go-undecided-receiver-candidates",
            "-7578-branch-conditioned-sanitizers",
            "-7618-java-creation-receiver-site",
            "-7560-csharp-row-backed-models",
            "-7348-7349-7369-java-compound-static-patterns",
            "-5658-single-writer-identity",
            "-5658-structural-module-mutations",
            "-5658-python-attribute-space-owners",
            "-5658-python-argument-independent-calls",
            "-5658-python-global-writer-identity",
            "-5658-python-native-member-targets",
            "-5658-python-native-production-switch",
            "-7642-witness-budget-incomplete",
            "-5658-python-unplaced-file-references",
            "-7516-go-constructor-shadow",
            "-7673-python-qualified-module-members",
            "-7817-external-supertype-kind",
            "-7868-closure-open-relations",
            "-7619-java-implicit-external-inherited-calls",
            "-7620-java-wildcard-sibling-applicability",
            "-7578-java-observed-value-type",
            "-7578-guard-writer-reachability",
            "-7735-binder-declaration-sites",
            "-5658-python-import-occurrence-kinds",
            "-7781-synthetic-members-completeness",
            "-7779-exact-selection-owner-inventory",
            "-7509-go-declaration-value-types",
            "-7755-refused-alternative-before-budget",
            "-3494-ruby-member-closure",
            "-7789-indexed-import-destinations",
            "-7849-java-external-owner-observed-type",
            "-7509-go-native-binding-proofs",
            "-2445-m4a-workspace-facts",
            "-qs13-flow-go-no-return-method-expressions",
            "-7350-nonbinding-rhs-distinct",
            "-qs13-flow-summary-payload-accounting",
            "-qs13-flow-typestate-byte-accounting",
            "-7918-go-field-selector-addressability",
            "-7536-initialization-retained-gaps",
            "-7915-flow-slot-identity",
            "-7508-csharp-conditional-branch-conversions",
            "-7803-external-field-value-types",
            "-2445-m4b-property-gaps",
            "-qs13-flow-store-error-kind-context",
            "-qs13-flow-taint-composition-quality",
            "-qs13-flow-call-transfer-canonical-order",
            "-7972-go-cross-file-global-self-assignment",
            "-7509-go-model-authority",
            "-7755-dead-value-liveness",
            "-7876-query-incompleteness-scope",
            "-7509-go-relative-source-imports",
            "-qs13-flow-value-flow-survivors",
            "-7351-go-error-method-set-proof",
            "-qs13-flow-field-slot-source-kinds",
            "-8036-go-native-external-callee-identity",
            "-qs13-rql-pending-cleanup-nested-scope",
            "-qs13-rql-python-loop-exit-and-docstring-blocks",
            "-7968-go-satisfaction-membership",
            "-8108-java-inventory-stable-replay",
            "-qs13-rql-configuration-property-ancestor",
            "-7509-g1b-incomplete-import-owner",
            "-8097-assignment-flow-gap-scope",
            "-3800-static-rooted-property-bases",
            "-7362-query-obligation-ledger",
            "-6664-incomplete-descendant-queries",
            "-7761-memo-fill-own-completeness",
            "-7505-member-ids-carry-signature",
            "-4379-m6-csharp-static-array-definitions",
            "-8146-boolean-patterns-unkinded-targets",
            "-4379-m6-csharp-nested-if-misleading-indentation",
            "-8148-binary-authority-inputs",
            "-4379-m6-csharp-rethrow-throw-sites",
            "-8153-ambiguous-binding-no-proven-target",
            "-8000-jvm-on-demand-external-candidates",
            "-qs13-rql-order-independent-fixed-points",
            "-7509-g1b-callable-result-slots",
            "-7153-cpp-field-guard-definitions",
            "-6945-curated-star-child-binding",
            "-8154-recursive-empty-arm-statements",
            "-7424-java-enum-switch-proof",
            "-8242-taint-endpoint-dominance",
            "-qs13-rql-file-joins-and-selected-property-admission",
            "-7240-imported-constructor-receivers",
            "-6234-kotlin-implicit-receiver-values",
            "-qs13-rql-source-and-language-survivors",
            "-8262-model-hierarchy-missing-endpoint",
            "-8264-go-predeclared-result-types",
            "-7509-g1b3-pointer-result-field",
            "-8147-m4a-csharp-preprocessor-decisions",
            "-8290-warm-closure-discharges",
            "-7314-c1-4b-csharp-native-demand",
            "-qs13-rql-python-search-survivors",
            "-7509-b-unexported-pointee-owner",
            "-8167-java-callable-family-evidence",
            "-8222-scala-implicit-root-order",
            "-8300-resolved-value-proven-near-miss",
            "-8305-field-write-call-ports",
            "-8201-stable-capped-index-reads",
            "-8486-stable-content-producer-diagnostics",
            "-7314-c1-4d1-csharp-qualified-heads",
            "-7314-c1-4d2-csharp-aliases",
            "-7314-c1-4d3-csharp-using-tiers",
            "-8403-rust-reverse-applicability-gaps",
            "-7314-c1-5a1-csharp-transient-membership",
            "-qs13-policy-source-survivors",
            "-7027-s2b-jvm-native-ancestors",
            "-7314-c1-5a2-csharp-global-aliases",
            "-qs13-policy-flow-survivors",
            "-7314-c1-5b-csharp-global-globs",
            "-7027-s2c-hierarchy-completeness",
            "-8411-static-openness-is-content",
            "-qs13-policy-catalog-identity-survivors",
            "-7509-g1b3-exact-binding-identity",
            "-7314-c1-5c-csharp-root-closure",
            "-7314-c1-4e-ad1-csharp-membership-unproven",
            "-7027-s3-native-descendants",
            // Provider-free Scala aliases must plan authored on-demand packages.
            "-8496-plan-provider-free-on-demand-packages",
            // Await results depend on the awaited value.
            "-8306-await-value-transfer",
            // Source-declared field-write targets project into policy evidence.
            "-7366-field-write-source-member-evidence",
            // C# call points are selectable; string equality guards are constant equality.
            "-8308-csharp-call-points-string-guards",
            "-8388-caller-inventory-coverage",
            // #8870: composed policies now bind declared entry formals as origins.
            "-8870-composed-entry-points",
            "-8457-rust-unenumerable-dispatch",
            "-8453-go-method-unenumerable-dispatch",
            // Go artifacts can come from parse-time rows, which admit by census.
            "-8402-go-parse-time-ir",
            "-7314-c1-4e-ad2-csharp-per-file-membership",
            // C# property-function imports change compilation membership.
            "-7314-ad3b-csharp-get-path-of-file-above",
            // Scala import and definition bindings use the SLS chapter 2 scope order.
            "-8279-scala-scope-shadowing",
            "-8147-m4b-csharp-parse-variants",
            // C# method groups remain open until call applicability and base search are modeled.
            "-7314-csharp-method-applicability-open",
            // Java, Kotlin and C# artifacts can come from parse-time rows.
            "-8579-native-parse-time-ir",
            // Java guarded switches lower instead of failing the switch contract.
            "-7750-java-guarded-switch-edges",
            "-7509-g1b3-f-nested-call-arity",
            "-8632-csharp-parent-relative-open-items",
            // Observer-free exceptional exits change flow relations and overwrite proofs.
            "-8602-exit-only-exceptional-routes",
            // On-demand lowering now uses the parse-time producer budget.
            "-8586-one-budget-at-materialization",
            // Scala import bridges retain context-owned qualifier boundaries.
            "-8665-scala-import-bridge-boundaries",
            // #8516: package member providers change selected policy bindings.
            "-8516-package-member-owner-providers",
            // A Scala implicit root's own binding keeps that root's gap open.
            "-8705-scala-implicit-root-own-gap",
            "-8147-m4c-csharp-unseen-branches",
            "-8831-csharp-target-property-scope",
            "-8845-csharp-multi-target-razor-paths",
            // Missing or unmodeled half rows no longer masquerade as cancellation.
            "-7314-demand-half-open-outcome",
            "-8667-go-nested-arity-gap",
            "-7509-g1b3-g-untyped-receiver-native-count",
            // Implicit JVM supertypes close member lookups through intrinsic roots.
            "-7027-s2b0-implicit-supertypes",
            // A JavaScript call's thrown value reaches the catch parameter.
            "-7960-js-call-throw-catch-binding",
            "-8790-go-path-index-stable-gap-replay",
            // JS/TS namespace import reads root property bases.
            "-8025-js-namespace-static-loads",
            // #8792: Kotlin explicit lambda names now have native lexical binders.
            "-8745-pre-kotlin-lambda-parameter-binders",
            // NuGet build asset imports retain project-local membership.
            "-8830-csharp-nuget-build-transitive-imports",
            // A JavaScript call's thrown value no longer reaches the catch parameter.
            "-8836-revert-js-call-throw-catch-binding",
            "-7509-3a-native-call-application-roles",
            "-8896-returned-member-ports",
            // Proven package-module identities survive neutral static-load evidence.
            "-8872-js-ts-package-module-identity",
            "-7509-m5b1-native-selector-refinement",
            // An unproven Go builtin assumption keeps an ICFG snapshot open.
            "-8388-icfg-go-builtin-assumptions",
            // Typed partitions separate root locator and compilation keys.
            "-8389-prefix-merge-suffix",
            "-7509-m5b2-native-allocation-refinement",
            "-7509-function-field-call-application",
            // Rust receivers through std unwraps bind modeled methods.
            "-8866-rust-unwrapped-receiver",
            // Rust external proofs read imports from the selected operation.
            "-8884-rust-selected-import-reads",
            // Closed C# inventory derivations change selected policy bindings.
            "-8822-csharp-inventory-closed-derivations",
            "-7509-m5b3-native-nested-call-result-counts",
            "-7869-package-boundary-per-alternative",
            // Cancelled procedure openness no longer reports Complete.
            "-8898-cancelled-procedure-openness",
            "-7509-retire-go-expression-inference",
            // C# enclosing namespace scope selection changes selected policy bindings.
            "-8803-csharp-enclosing-namespace-scope",
            // #8870: composed store links change policy answers and reads.
            "-8870-composed-store-ends",
            "-8487-java-on-demand-package-outcomes",
            "-8992-jvm-on-demand-declaration-admission",
            // A reused unit charges the same cumulative allowance as a recomputed unit.
            "-8389-charge-reused-units",
            // Union suffixes now run after the per-seed set merge.
            "-8389-union-seed-local-suffix",
            "-7509-go-structural-signature-identity",
            "-7509-m5b4b-native-function-value-proof",
            // #8996: stored base evaluations exclude head-only NotRun policies from reliability.
            "-8996-diff-base-reliability",
            "-7509-m5b4a-selected-aggregate-owner",
            "-8963-go-result-obligation-coverage",
            "-8870-composed-conditional-sanitizers",
            // #8870: candidate explanations consume composed store crossings.
            "-8870-store-ended-candidates",
            // #8870: complete flow endpoint inventory changes policy read receipts.
            "-8870-composed-flow-policies",
            // #8991: a by-value let of a struct publishes an Allocation for its storage.
            "-8991-rust-let-copy-allocation",
            // Native declared effects use the shared execution relation.
            "-2508-native-composed-effects",
            // #8978: Rust branch values join into their expression result.
            "-8978-rust-branch-value-join",
            // Rooted Java expression prefixes change selected policy bindings.
            "-7804-java-fqn-expression-prefix",
            "-8389-intersect-prefix-reuse",
            // Root set operators reuse typed per-seed operands before a global suffix.
            "-8389-set-prefix-reuse",
            // A reused typestate root is admitted only if it fits every lane.
            "-8389-typestate-root-fit",
            // Composed outputs are reusable by stable reported site.
            "-8389-native-output-units",
            // #9013: a Rust call condition is a Truthy guard.
            "-9013-rust-call-guard-truthy",
            // Java selected contexts now use the shared JVM assembly.
            "-7314-m1f-java-common-import-context",
            // #9063: certified Go promotion collisions leave the method set.
            "-9063-go-certified-method-collision",
            // #9084: whole-declaration findings anchor on the declaration identity.
            "-9084-declaration-finding-anchors",
            // Implicit-root edges close without reading the mutable identity claim.
            "-8741-implicit-root-edges-order-independent",
            // Selected JVM root decisions are now verified before policy-unit reuse.
            "-8834-root-presence-read-key",
            // #8811: a previously closed relation replays its discharge to each request owner.
            "-8675-pre-closed-relation-discharge-replay",
            // Reached value-flow rows use a plan/event pair identity across engines.
            "-8386-value-flow-neutral-endpoint-ids",
            // #9127: the public plan fingerprint in endpoint IDs is mount-free.
            "-9127-mount-free-value-flow-plan-identity",
            // #8940: continuation heap ports change composed policy answers.
            "-8940-post-call-heap-ports",
            // ICFG member input follows content-preserving argument copies.
            "-8896-icfg-member-call-bindings",
            // #9162: one seed key per partial-flow port changes stored partial-flow rows.
            "-9162-partial-flow-seed-canonicalization",
            // #8962: CallEffects windows and grant-neutral artifact row charges change admissions.
            "-8962-semantic-artifact-window-admission",
            // Nested Rust proofs reuse the held selected operation.
            "-8893-rust-selected-operation-reuse",
            // #9196: certified closure invocation and Rust local dispatch affect answers.
            "-9196-closure-invocation-certificates",
            // #9230: an incomplete native caller inventory makes RQL call relations incomplete.
            "-9230-rql-native-caller-inventory",
            // #9060: completed typed-round call results rotate retained policy units.
            "-9060-typed-round-ready-queue",
            // #9195: native Scala selected alias parents change retained dispatch answers.
            "-9195-native-scala-alias-parents",
            // #9195: exact Scala reference package contexts change retained hierarchy answers.
            "-9195-scala-reference-package-contexts",
            // #9323: Kotlin static JDK calls change retained policy answers.
            "-9323-kotlin-jdk-static-calls",
            // #9220: renamed JVM object-member imports change selected answers.
            "-9220-jvm-renamed-member-imports",
            // #6291: corrected native Java call bindings change retained policy answers.
            "-6291-native-java-call-binding-corrections",
            // #6792: bare Scala term binding changes retained policy answers.
            "-6792-scala-bare-term-bindings",
            // #8389: file-local set minuends slice by seed instead of running whole.
            "-8389-file-local-set-minuend",
            // #7654: selected Object members change retained Scala call answers.
            "-7654-scala-anyref-object-members",
            // #9097: store crossings keep their source event in witnesses.
            "-9276-store-witness-source-sites",
            // #8389: root unions of file-local set subtrees slice by seed.
            "-8389-root-union-file-local-set",
            // #8386: ready Go value flow selects composition.
            "-8386-go-composed-value-flow",
            // #8870: Go conditional sanitizers select composition.
            "-8870-go-conditional-composition",
            // #8826: restored C# undecided-chain scans add retained evidence gaps.
            "-8826-csharp-undecided-scan-receipt",
            // #7509: sole-spec Go alias ownership changes retained answers.
            "-7509-go-sole-alias-owner",
            "-8386-composed-rowless-sink-artifacts",
            // #9270: partial C# yield continuation changes retained policy answers.
            "-9270-csharp-yield-normal-continuation",
            // #8826: C# global-using memo admission changes retained answers.
            "-8826-query-memo-admission",
            // Rust lifecycle object composition and receiver-mode proofs change answers.
            "-8386-typestate-composition",
            // #9263: selected Rust Copy-absence proof changes query-time ownership answers.
            "-9263-rust-copy-absence",
            // #9277: scoped Go native context availability changes retained answers.
            "-9277-go-selected-context-reconciliation",
            // #7960: JS call throws reach catch binders, resolved per definition.
            "-7960-reland-js-call-throw-definition-alternatives",
            // #9378: indexed modeled call results close.
            "-9378-indexed-modeled-call-results",
            // #9378: result-contract seeds start on their activation edge.
            "-9378-composed-result-activation",
            // #9378: Go pointer handoffs certify composed typestate continuity.
            "-9378-go-pointer-handoffs",
            // #9412: certified Scala enclosing-package members suppress default-import gaps.
            "-9412-scala-local-package-precedence",
            // #7509: directional Go channels change selected method signatures.
            "-7509-go-channel-direction-identity",
            // #9330: PHP element reads and concatenation lower operand flows.
            "-9330-php-element-concat-flow",
            // #9331: PHP interpolated strings flow their parts.
            "-9331-php-string-interpolation-flow",
            // #9203: owned Rust receiver events change retained bindings and results.
            "-9203-rust-owned-receiver-events",
            // #9438: decorator argument roles change existing arity answers.
            "-9438-decorator-argument-arity",
            "-9438-decorator-comment-parens",
            // #9431: lifecycle coverage claims change selected external-call answers.
            "-9431-lifecycle-coverage-claims",
            // #9060: semi-naive typed rounds complete more retained policy units.
            "-9060-semi-naive-typed-rounds",
            // #8723: recorded C# branch obligations reach structural answers.
            "-8723-read-reasons-reach-structural-answers",
            // #9432: modeled imported-formal authority changes composed typestate answers.
            "-9432-go-modeled-imported-formal-authority",
            // #9486: modeled producer origin certificates change composed typestate answers.
            "-9486-modeled-producer-origin",
            // #9532: Java proofs over formals with unproven type arguments change call bindings.
            "-9532-java-external-formal-type-arguments",
            // #7365: attribute predicates now withhold unsupported structural answers.
            "-7365-declaration-attribute-capability",
            // #9561: negated and Boolean-composed features now withhold unsupported answers.
            // #9582: complete empty operand-zero probes avoid evaluating later set operands.
            "-9561-negated-feature-capability",
            // #4379 M4b: C# declarations now expose their modifiers and type kinds.
            "-4379-m4b-csharp-declaration-attributes",
            "-9522-receiver-incomplete-candidates",
            // #9557: member families name certified unread ancestors and language roots.
            "-9557-native-java-unread-ancestors",
            // #8870: Java static on-demand imports now leave the reverse target incomplete.
            "-8870-java-static-import-reverse-completeness",
            // #8389: merged typestate union rows now provide selected sites.
            "-8389-typestate-set-union-slice",
            // #9595: withheld prefix continuations now preserve the prefix cause.
            "-9595-prefix-coverage-reasons",
            // #8870: nested Java reverse targets open uncertified inherited routes.
            "-8870-java-nested-reverse-owners",
            // #8675 S2: every carried Java Type-frontier gap occurrence must be proven before discharge.
            "-8675-s2-java-type-frontier-authority",
            // #9575: Python mutation reads rescan instead of reusing stopped or unreceipted outcomes.
            "-9575-python-mutation-read-admission",
            // #9447: formal-role refusals and stable local Go literal targets/captures change answers.
            "-9447-structured-formal-roles",
            // #9614: Boolean attribute predicates inherit their enclosing fact kind.
            "-9614-attribute-kind-inheritance",
            // #9612: kind filters treat unclassified reference sites as undecided.
            "-9612-unclassified-reference-kinds",
            // #9546 M1a: selected Java type-name decisions and refused ambiguous member prefixes.
            "-9546-m1a-selected-import-authority",
            // #9582: empty operand-zero probes change retained set-prefix answers.
            "-9582-prefix-intersect-short-circuit",
            // #9563: owned and read query-node obligations survive semi-naive rounds.
            "-9563-semi-naive-query-node-obligations",
            // #8870: Java caller inventories require the reference execution frame to certify caller identity.
            "-8870-java-reference-callable-context",
            // #7857: provider-qualified modelled candidates and selected Python model-member trace rows.
            "-7857-modeled-member-candidates",
            // #9002: protected lexical head reasons reach JVM qualified-name continuations.
            "-9002-jvm-lexical-head-blockers",
            // #9617: reference facets change retained policy edge rows and completeness.
            "-9617-reference-kind-facets",
            // #7040: public Rust diagnostic evidence now names the selected workspace path.
            "-7040-rust-gap-diagnostic-path",
            // #5658 M8: file-local Python call lowering changes retained policy answers.
            "-5658-python-file-local-lowering",
            "-5658-python-with-suppression-candidate-edges",
            // #9779: C++ macro-recovery owners and proven recovered formals change C++ answers.
            "-9779-cpp-recovered-lexical-formals",
            // #9658: composed terminal provenance changes retained root findings.
            "-9658-composed-terminal-provenance",
            // #9743: composition call-result origin proof order changes retained completion and findings.
            "-9743-composition-call-result-origin",
            // #9612: access-position facets change retained policy edge rows.
            "-9612-field-access-facets",
            // #8500: certified external-owner targets, per-owner obligation retirement and
            // Unproven reverse edges while query obligations are outstanding.
            "-8500-certified-owner-targets-and-reverse-obligations",
            // #9810: Go field access positions change retained edge rows.
            "-9810-go-field-access-facets",
            // #9183 (-9183-typestate-alias-guards): callee footprint certificates, shared gap reconciliation, the F1 subject witness and F2 exclusion, conditional-presence alias guards, and mount-independent binding-plan identity change typestate answers and root reuse.
            "-9183-typestate-alias-guards",
            // #9550/#9566: uncovered summary dimensions refuse Complete reuse.
            "-9550-call-closure-honest-summaries",
            // #9651: formal member overwrites kill earlier member values.
            "-9651-formal-member-overwrite",
            // #9835: explicit Rust call results use sparse formal ordinals.
            "-9835-rust-positional-generic-results",
            // #9868: missing binder observations change retained policy completion.
            "-9868-unknown-binder-source-refusal",
            // #9784: stored semantic IR publication reads become recorded, verified receipts.
            "-9784-stored-semantic-ir-read-admission",
            // #9863: first visible unreachable Rust regions change retained answers.
            "-9863-rust-first-unreachable-region",
            // #9863 M2: Rust binding identity and access completeness change retained rows.
            "-9863-rust-binding-access-facts",
            // #9773: Java plain and compound assignments now decide field reads.
            "-9773-java-assignment-operator",
            // #9746: composition typestate roots publish and replay as root products.
            "-9746-composition-root-publication",
            // #9687 E1: Rust result producers and value-join transfers change retained answers.
            "-9687-e1-rust-result-producers",
            // #9783: selected explicit-import owners change reference targets, definitions and completion.
            "-9783-selected-import-owner-publication",
            // #9840: warm updates carry verified dependency-discovery evidence.
            "-9840-warm-activation-carry",
            // #9934: wildcard assignment no longer opens the procedure.
            "-9934-rust-wildcard-assignment-discard",
            // #9852: uncertified external Go signature leaves keep dispatch proof open.
            "-9852-go-external-leaf-certification",
            // #9971: edge rows now retain a source-anchored policy finding.
            "-9971-edge-match-candidates",
            // #9879: admitted Go scoped call/control coverage restores Complete roots.
            "-9879-go-scoped-call-control-claims",
            // #9324: an inapplicable external overload no longer opens an access gap.
            "-9324-inapplicable-external-access-gaps",
            // #10014: exact receiver call bindings select receiver sinks under incomplete discovery.
            "-10014-receiver-taint-rows",
            // #9971: adapted edge steps preserve complete finding provenance.
            "-9971-edge-provenance",
            // #9444: Rust pattern-name and closure capture contract.
            "-9444-rust-pattern-capture-contract",
            // #9546: Java usage-evidence cache hits replay their producer's read receipt.
            "-9546-java-usage-evidence-receipt-replay",
            // #9224: the target-keyed Go match changes selected reverse answers.
            "-9224-go-target-keyed-reverse-match",
            // #10106: unprovided written Go types stay open.
            "-10106-go-external-member-unprovided",
            // #10134: pre-attribution rows may contain approximate models but lack receipts.
            "-9855-close-match-1b-finding-attribution",
            // #9866: rooted call-site reachability and dispatch projection change policy answers.
            "-9866-rooted-call-reachability",
            // #9319: exact Gemfile.lock gems are Ruby activation evidence.
            "-9319-ruby-gem-lock-activation",
            "-9863-localized-statement-reachability",
            // #10021: creation types follow their qualifier, not constructor selection.
            "-10021-creation-type-from-qualifier",
            // #10050: retained configuration rows must carry the sibling-directory key.
            "-10050-configuration-directory-field",
            // #10050: element bases and subtree scope change persisted absence answers.
            "-10050-scoped-configuration-absence",
            "-9863-rust-feasible-literal-guards",
            "-10045-authored-family-precedence",
            // #7708: declared type arguments reach Java overload applicability.
            "-7708-declared-type-argument-transport",
            // #10166: workspace inventory excludes analyzer-owned cache files.
            "-10166-inventory-excludes-analyzer-cache",
            // #10161: exact Go typed-var call-result identity.
            "-10161-go-typed-var-call-result-identity",
            // #10168: a captured Go local counts only writers reaching registration.
            "-10168-reaching-writer-at-capture",
            // #9737: recorded derivation reads now verify policy-unit reuse.
            "-9737-recorded-derivation-inputs",
            // #10058: receiver-determined member identity.
            "-10058-receiver-determined-member-identity",
            // #9642: typestate protocol coverage admission.
            "-9642-protocol-coverage-admission",
            // #9766: separated copy joins retain return-member provenance.
            "-9766-separated-join-members",
            // #9324: Scala JDK overload answers use the closed JVM hierarchy.
            "-9324-scala-reference-conversions",
            // #10097: Output receipts may carry a role-name lookup kind.
            "-10097-role-name-inventory-receipts",
            // #9947: Output products record effective composition limits.
            "-9947-m2a-replayable-output-diagnostics",
            // #9995: Scala library call answers use companion apply and known-head refutation.
            "-9995-scala-library-owner-inventories",
            // #5658 M8 step 1a: Python definition dispatch answers from native selected resolution.
            "-5658-python-native-definition-dispatch",
            // #10181: Go call results are selected by ordinal for typed-var identity.
            "-10181-go-multi-result-call-identity",
            // #9947 M2b part 1: certified selector gaps are content and selector memo hits replay reads.
            "-9947-m2b-selector-gap-content",
            // #5658 M8 P1: a proven classmethod receiver discharges its own parameter gap.
            "-5658-python-classmethod-receiver-gaps",
            // #10384: js/misspelled-identifier skips intrinsic JSX tag names.
            "-10384-misspelled-jsx-intrinsic-tags",
            // #10385: external JVM member access is decided per caller.
            "-10385-caller-decided-external-member-access",
            // #5658 M8 P2: subscripted and union annotations name their outer class or members.
            "-5658-python-annotation-application-heads",
            // #8675 S3: Scala term-path heads and qualified members.
            "-8675-s3-scala-term-path-heads",
            // #10388: declaration-scoped JVM producer gaps change retained completions.
            "-10388-jvm-declaration-scoped-producer-gaps",
            // #9925 M1a: guarded pattern projection candidates.
            "-9925-rust-ownership-unknown-projections",
            // #7643: different-owner supertype projection reaches Java overload applicability.
            "-7643-supertype-argument-projection",
            // #10386: js/misspelled-identifier reports only known misspellings.
            "-10386-known-misspelling-typo-table",
            // #10266: capped Output runs keep completed anchors and cap surviving findings.
            "-10266-capped-output-prefix",
            // #10433: imported external Python bases are external, not failed inference.
            "-10433-python-external-base-not-inference-failure",
            // #9947 M2b part 2: Unsupported snapshot promotion is content unless execution-dependent.
            "-9947-m2b-snapshot-execution-cause",
            // #10445: Scala parameter activation changes retained resolution and dispatch answers.
            "-10445-scala-parameter-clause-activation",
            // #5658 M8 P3: a Python call's callee carries only the callable result.
            "-5658-python-callee-callable-result-only",
            // #7262: composition run-memo hits replay the dispatch, evidence and std builtin receipts of their fill.
            "-7262-composition-memo-hit-receipts",
            // #9947 review fix: witness and lost-snapshot interiors keep their cause.
            "-9947-interior-snapshot-causes",
            // #5658 M8 P5: a one-hop module alias qualifier is a namespace.
            "-5658-python-module-alias-qualifier",
            // #10400: the promotion status and cause come from the file-local projection.
            "-10400-file-local-promotion-status",
            // #10020: a Scala or Kotlin member-selection leaf no longer binds a same-named local.
            "-10020-jvm-member-selection-not-lexical",
            // #7262 F6: Rust route and package memo hits replay their fill receipts.
            "-7262-rust-route-memo-hit-receipts",
            // #5658 M8 P4: a qualified nested class definition reports its identity.
            "-5658-python-qualified-class-definition-identity",
            // #7860: receiver type arguments are substituted into Java external member signatures.
            "-7860-receiver-type-argument-substitution",
            // #7262 F7: Rust walk-cache hits replay their fill receipts.
            "-7262-rust-walk-cache-hit-receipts",
            // #10466: a rejected return member is a content gap, not a Truncated snapshot.
            "-10466-rejected-return-member-content-gap",
            // #10000: external Java constructor families bind overloads from argument types.
            "-10000-java-external-constructor-families",
            // #9991: effect-bearing external summaries bind through keyword mappings.
            "-9991-mapped-summary-effects",
            // #9988: Go conversion origins are validated (row missing when it landed).
            "-9988-go-conversion-origin-validation",
            // #7860 slice 2 A: a field-named Java external method keeps its member identity.
            "-7860-callable-member-identity",
            // #10399: Outputs carry only consulted source-binding refusals, typed by cause.
            "-10399-scoped-source-binding-refusals",
            // #9987: composed transforms to a call result are placed by their ports.
            "-9987-transform-output-port-placement",
            // #10088: bounded traversal completion changes retained policy answers.
            "-10088-depth-bound-reached",
            // #9981: a provably inconvertible actual no longer binds the only layout-compatible member (row missing when it landed).
            "-9981-csharp-single-overload-applicability",
            // #9869: Go calls in build-constrained source-inventory files are not complete bindings (row missing when it landed).
            "-9869-go-constrained-source-inventory-callers",
            // #10539: one event's alternatives join instead of killing each other.
            "-10539-simultaneous-alternatives-join",
            // #10432: call-row conversions use the selection's type-argument bindings.
            "-10432-binding-substituted-call-conversions",
            // #5658 M8: Python type flow takes native type answers.
            "-5658-python-native-type-switch",
            // #10560: the taint fallback starts from a value-restored budget and memo.
            "-10560-fallback-budget-value-restore",
            // #9332: omitted formals with published saved defaults are complete bindings.
            "-9332-omitted-saved-default-bindings",
            // #10530: the strong-update question closes its scratch evidence admission.
            "-10530-scratch-admissions-closed",
            "-10759-procedure-scoped-guard-selection",
            "-10596-rust-manifest-file-identity",
            // #10582: query-time Go interface argument conversions.
            "-10582-go-interface-boxing-conversions",
            // #10403: a semantic budget stop belongs to the Output unit it truncated.
            "-10403-unit-scoped-semantic-budget-stop",
            // #10229: C# member form and trivial-property step options change retained rows.
            "-10229-csharp-member-form",
            // #10563: a read through a stored reference follows the stored object, or is partial.
            "-10563-reference-prefix-alternative-paths",
            // #8804: the exceptional continuation relays a thrown value to the caller's return port.
            "-8804-relayed-exceptional-returns",
            // #10694: a Go source refused after parsing is a named graph exclusion.
            "-10694-go-refused-file-graph-complete",
            // #10052: C# Fenced pack owner and member-family dispositions change retained answers.
            "-10052-csharp-fence-dispositions",
            // #7314 AD3d: ordered MSBuild property evaluation changes C# membership.
            "-7314-ad3d-ordered-msbuild-properties",
            // #10812: model overloads are selected by actual types, not the written count.
            "-10812-model-overload-applicability-by-type",
            "-10530-unit-scoped-ledger",
            // #9925 M1b2: a selected Poem field binder is a matched-value source and its witness records the admission.
            "-9925-rust-admitted-binder-discharge",
            // #10683: an identity field copy no longer redirects a longer access into its own cell (row missing when it landed).
            "-10683-identity-prefix-stores",
            // #10783: a typestate subject passed to an unresolved call keeps a possible normal continuation (row missing when it landed).
            "-10783-unresolved-call-subject-continuation",
            // #8854: a qualified locator with no file in the plan's languages stays unresolved (row missing when it landed).
            "-8854-absent-language-locators",
            // #10687 B: a call whose argument conversion may run a user Deref keeps its transfer incomplete.
            "-10687-conversion-weakened-call-transfers",
            // #7314 AD3d EC2 r5: three-valued MSBuild conditions change C# membership.
            "-7314-ad3d-msbuild-condition-short-circuit",
            // #8430: grammar 0.23.9 parses namespace-body extern aliases as directives.
            "-8430-csharp-grammar-0-23-9",
            // #10770 slice 1: typed method and operator results flag fewer conversions.
            "-10770-method-operator-result-types",
            // #10881: a constant short-circuit operand may keep only its selected arm.
            "-10881-folded-operand-arms",
            // #10846: a flagged conversion keeps a possible unchanged-subject continuation.
            "-10846-unproven-conversion-continuation",
            // #10770 slice 2a: Self and model-backed result types flag fewer conversions.
            "-10770-self-and-model-result-types",
            // #10774: RUST_CRATE_DERIVATION_VERSION and POLICY_SUBSTRATE_EPOCH move together.
            "-10774-manifests-only-cargo-toml",
            // #10987: directory omissions affect only reachable Rust topology.
            "-10987-scoped-symlink-omissions",
            // #10470: read completeness of JVM lookups changes for unchanged inputs.
            "-10470-per-lookup-dependency-gaps",
            // #10770 slice 2b: generic result types flag fewer conversions.
            "-10770-generic-result-types",
            // #10802: log package identity and the unknown macro argument guard.
            "-10802-log-package-identity",
            // #10770 slice 2c: operator Output result types flag fewer conversions.
            "-10770-operator-output-types",
            // #9687 E2: removing the blanket Rust tail gap changes retained answers.
            "-9687-e2-rust-tail-gap-removal",
            // #10953: RUST_CRATE_DERIVATION_VERSION and POLICY_SUBSTRATE_EPOCH move together.
            "-10953-target-dependencies-and-lib-names",
            // #9737 c2: partial Rust crates answer route questions unknown, not negative.
            "-9737-route-completeness",
            // #9766: dead Rust block normal ends no longer define values.
            "-9766-block-dead-fallthrough",
            // #10269: glob-imported pattern names are Unknown; braced-struct names bind.
            "-10269-rust-pattern-glob-braced-struct",
            // #11022 J1: Java method signature and body footprint claims.
            "-11022-java-footprint-j1",
            // #4307: std receiver adjustment chains and guard admission.
            "-4307-rust-std-deref-summary-chain",
            // #10989 M0: closed local maps keep constant keys in separate cells.
            "-10989-closed-container-key-cells",
            // #11014: Java try-with-resources close selection changes policy call answers.
            "-11014-twr-close-member-selection",
            // #10952: recorded Rust inventory lookups replace the interim markers.
            "-10952-recorded-inventory-lookups",
            // #11036: a crate-local log item shadowing the dependency refuses log macros.
            "-11036-log-shadow-refusal",
            // #8296: C# model overloads select the member that exactly matches its actuals.
            "-8296-csharp-exact-match-overloads",
            // #10985 M1: candidate outcomes and setup receipt admission.
            "-10985-m1-candidate-outcomes",
            // #9737 step d: conversion proofs abstain on partial routes.
            "-9737-step-d-conversion-routes",
            // #11069: declaration_facts hits replay the fill's complete receipt.
            "-11069-declaration-facts-hit-receipts",
            // #11089: typed inventory gaps and independent candidate completion.
            "-11089-unready-inventory-incompleteness",
            // #11060: a declared module without a source blob keeps its topology partial.
            "-11060-unplaced-module-topology",
            // #8297: C# reduced-form calls bind model-declared extension methods.
            "-8297-csharp-model-extension-methods",
            // #8430 step 2: extern alias facts change alias-qualified C# answers.
            "-8430-extern-alias-facts",
            // #7314 M10a0: named-open configuration symbols change retained policy answers.
            "-7314-m10a0-per-framework-symbols",
            "-7314-m10a0-named-open-symbols",
            // #11111: certified-absent Rust modules preserve broad completeness.
            "-11111-certified-absent-module-topology",
            // #10342: only gaps that can hide a global using open the global-using inventory.
            "-10342-global-using-enumeration-evidence",
            // #8430: alias-only ::, namespace continuation, CS0431, extern/conflict
            // boundaries; alias absence requires complete global-using read B.
            "-8430-alias-qualified-consumer",
            // #10985 M2a: typestate compilation and evaluation answers for partially decided subject selectors.
            "-10985-m2a-subject-selection",
            // #11146: qualifying-type unit discharge changes seeded policy-unit merge results.
            "-qualifying-type-unit-discharge",
            // #4967 C: the ? residual proof binds generic alias parameters.
            "-4967-residual-alias-parameters",
            // #7314 M6a1: declared type slots and global predefined aliases.
            "-7314-m6a1-csharp-declared-types",
            "-11131-undecided-row-predicates",
            // #4967 C slice 3: an awaited direct async fn call types the ? residual.
            "-4967-residual-await-call",
            "-11169-resolved-callee-provenance",
            // #10497: external intermediate supertypes join or open JVM dispatch families.
            "-10497-external-intermediate-supertypes",
            // #10985 M3: exclude starting acquisitions before typestate enumeration.
            "-10985-m3-typestate-seed-scope",
        ] {
            assert_eq!(POLICY_SUBSTRATE_EPOCH.matches(component).count(), 1);
            let old_substrate = POLICY_SUBSTRATE_EPOCH.replacen(component, "", 1);
            let old_epoch = StableDigest::sha256(format!(
                "{old_substrate}\u{1}{}\u{1}{}",
                analysis_epoch_digest(),
                StableDigest::sha256("test-lowering"),
            ));
            for models in [
                StableDigest::sha256(NO_ACTIVE_MODELS),
                StableDigest::sha256("same active model set"),
            ] {
                let current = WorkspaceUnitInputs {
                    model_read_digest:
                        brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(None),
                    configuration: StableDigest::sha256("same configuration"),
                    models,
                    epoch: policy_substrate_epoch(StableDigest::sha256("test-lowering")),
                };
                let old = WorkspaceUnitInputs {
                    model_read_digest:
                        brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(None),
                    epoch: old_epoch,
                    ..current
                };
                let current_key = current.unit_key(policy, UnitPartition::Whole);
                let old_key = old.unit_key(policy, UnitPartition::Whole);
                assert_eq!(current_key.models, old_key.models);
                assert_ne!(
                    row_key(&current_key),
                    row_key(&old_key),
                    "persisted unit lookup must miss an old substrate product"
                );
                assert_ne!(
                    current.head_inputs(policy).epoch,
                    old.head_inputs(policy).epoch,
                    "aggregate evaluation/read verification must not reuse old substrate semantics"
                );
            }
        }
    }

    /// The reuse review is charged to the report's retention budget, so its
    /// retained size must not say how the run executed. Two reviews of one
    /// policy set -- the one a reusing run records and the one a forced-full
    /// run records -- therefore cost the same bytes, and every later retention
    /// decision sees the same remaining budget in both modes.
    #[test]
    fn a_reusing_and_a_forced_full_review_retain_the_same_bytes() {
        let sliced = PolicyId::new("test.dynamic-eval").expect("policy id");
        let whole = PolicyId::new("test.taint-flow").expect("policy id");
        let reusing = PolicyIncrementalReview {
            base: IncrementalBaseState::Reused,
            policies: vec![
                PolicyIncrementalRun {
                    policy_id: sliced.clone(),
                    mode: IncrementalMode::Sliced,
                    units_total: 40,
                    units_reused: 39,
                    units_recomputed: 1,
                    units_unbounded: 0,
                    lookups_replayed: 0,
                    output_refusals: Default::default(),
                    composition_searches: Default::default(),
                    discarded_source_inventory: None,
                    widen_reason: None,
                    widen_detail: None,
                    base_units_reused: 38,
                    base_units_recomputed: 2,
                    base_lookups_replayed: 0,
                    base_widen_reason: Some(WidenReason::MergedLimitReached),
                    base_widen_detail: None,
                },
                PolicyIncrementalRun::whole_family(whole.clone()),
            ],
        };
        let forced_full = PolicyIncrementalReview::evaluated_in_full(
            [sliced, whole],
            WidenReason::IncrementalDisabled,
        );

        assert_eq!(
            reusing.policies().len(),
            forced_full.policies().len(),
            "both modes report every policy that ran"
        );
        assert_eq!(reusing.retained_size(), forced_full.retained_size());
    }
}

#[cfg(test)]
#[path = "units/policy_source_identity_tests.rs"]
mod policy_source_identity_tests;
