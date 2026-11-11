//! Demand-materialized, language-neutral interprocedural control flow.
//!
//! Callable CFGs remain immutable and procedure-local. This module stitches a
//! bounded, generation-local view on demand and never builds an eager
//! whole-workspace graph.

use std::fmt;
use std::sync::Arc;

use crate::analyzer::semantic::read_ledger::ReadKey;

use brokk_bifrost_core::analyzer::model::Language;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmWork;

use crate::analyzer::semantic::cfg_algorithms::forward_reachability;

use crate::analyzer::semantic::cfg_algorithms::reverse_reachability;

use crate::analyzer::semantic::completeness_reason_bytes;

use crate::analyzer::semantic::workspace_oracle::semantic_locator_work;

use crate::analyzer::semantic::ArgumentCallableProvenance;

use crate::analyzer::semantic::CallContinuationKind;

use crate::analyzer::semantic::CallInvocationMode;

use crate::analyzer::semantic::CallSiteHandle;

use crate::analyzer::semantic::CallSiteId;

use crate::analyzer::semantic::ControlContinuation;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::DeferredInvocationKind;

use crate::analyzer::semantic::DispatchBoundaryKind;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::EvidenceHandle;

use crate::analyzer::semantic::FormalMultiplicity;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleLimits;

use crate::analyzer::semantic::OracleRelationArena;

use crate::analyzer::semantic::OracleRelationHandle;

use crate::analyzer::semantic::OracleRelationId;

use crate::analyzer::semantic::OracleRelationKind;

use crate::analyzer::semantic::OracleRelationOwner;

use crate::analyzer::semantic::OracleRelationRecord;

use crate::analyzer::semantic::OracleRelationSubject;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProgramPointHandle;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapKind;

use crate::analyzer::semantic::SemanticGapSubject;

use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticValue;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

#[doc(hidden)]
pub const DEFAULT_ICFG_PROVIDER_BEHAVIOR_DOMAIN: &[u8] =
    b"bifrost-icfg-provider/default-behavior/v1";
// Shared copied-member and return-port transport changes provider answers even
// when a language artifact is unchanged. Rotate both persisted behavior halves
// so field surveys, class-set roots and read-verified summaries cannot reuse
// answers produced before that transport was represented (#2848), before
// construction results were separated from initializer returns (#3347), or
// before Python bound-method dispatch accounted for receiver lookup hooks.
// Module-qualified Python constructors now bind their allocated instance
// without treating the module namespace as a runtime receiver, including
// calls through repeated unaliased imports of one dotted package root,
// resolver-proven from-imported submodules, and their local aliases (#4492).
// Nested class attributes and module namespaces imported in conditional
// branches use the same constructor allocation result (#4564).
// A Go call through a package variable now dispatches to its function-literal
// initializer when a workspace usage census proves the variable is never
// written, escaped, or read as a value (#3787).
// Factory callback provenance, matched-return capture transport and captured
// formal cell initialization change the executable flow and heap semantics.
// Go handler dispatch accepts reference sites whose roots omit trivia (#4811).
// Structured callee spines reject calls of values instead of binding them to
// names inside the callee expression (#5019).
// Native Kotlin points change call/definition answers consumed by persisted
// field and class-set results, independently of graph backend authority.
// Usage classification feeds incoming projection consumed by the field-slot
// survey and incoming-actual discovery (#7289).
// Go nested call result counts and resolver-proven static Go calls change call-binding and dispatch answers (#7150).
// A Rust method call on a concrete receiver publishes call-local closed dispatch, so its override gap closes without a member-family proof (#7219).
// An unproven member family no longer proves that a concrete callee has no
// override, so those calls keep their dispatch gap open (#7183).
// Incomplete member families carry their established edges, and dispatch
// offers them as possible targets (#7179 step B).
// C# incoming relations prove exact overload targets (#7464).
// Go open member calls record receiver places and change member call, receiver flow and binding answers (#7150).
// Go interface-dispatch edges to concrete targets are References, unproven while the dispatch is open (#7519, #7520).
// #7471: Short-var redeclarations and receiver shadowing select the declared binding.
// #7470: Case-local and variadic bindings change inferred receiver and call answers.
// #7470: Labeled and statement-header declarations retain their own binding identity.
// #7618: Java type-reference receiver classification changes native call binding.
#[doc(hidden)]
// Python deferred reads of a single writer have fixed identity, and loop reads
// stay open only for writes of their own cell in that loop (#5658).
// Deferred Python module reads use structural mutation receivers (#5658).
// Python attribute-space reads count only structural owners' writes (#5658).
// Python calls bind without demanding their arguments (#5658).
// #7179: dispatch closure uses descendant completeness independently of ancestors.
// A sole global or nonlocal writer in another execution fixes Python identity (#7514).
// Rust Deref receiver steps change selected callees for unchanged source
// bytes (#7226).
// #7202: external result identity requires a classified summary transfer.
// Results of calls into source-less Go packages stay unknown (#7616).
// Unnamed Go composites publish direct type shapes (#7617).
// #7518: native Go reverse keeps undecided-receiver candidates unproven, which
// changes incoming answers that dynamic-store surveys consume.
// #7578: branch-conditioned sanitizers install label-narrowed condition-edge kills.
// CLR special member names split at the right dot, and semantic-model composition reads only its group's language, so C# modeled constructor calls and composed members change for unchanged source bytes (#7560).
// #7516: Go constructor shadows no longer seed package receivers, so incoming
// answers change.
// #7578: requirement origins use definitions reaching the operand, including loop backedges.
// #7619: inherited external JVM methods now publish selected callable targets.
// #7620: Java wildcard sibling applicability changes query-time call proofs.
// #6234: bare Kotlin value bindings now check implicit receivers.
// #7509 M3a: Go type answers at declaration names come from the declaration
// value slot, so value-type barrier observations change for unchanged bytes.
// #3494: closed Ruby member selections discharge their dispatch gaps.
// #7789: imports of provider-indexed JVM types are no longer unindexed boundaries.
// #7849: Java observed value types name selected external owners such as java.nio.file.Path.
// #7509 M3a part 2: Go failure-handler binding proofs come from native
// binder selection and declared slots, so handler shapes change for unchanged bytes.
// Quicksilver round 13: Go non-return discovery admits method expressions that
// write the receiver as an argument, so flow-state control changes for unchanged bytes.
// #7918: Go field selections through addressable or pointer receivers admit
// pointer-receiver methods, so receiver and call answers change for unchanged bytes.
// #7915: flow carrier comparison follows the carrier key, so plans that held one
// slot both plain and substituted now build instead of refusing.
// #5658 switches production Python query answers to the native engine.
// #7803: external field values share declared type materialization with call results.
// #7779: exact owner-declared calls close open external member inventories.
// #7509 PR B: native Go model-owner selection changes receiver and call answers.
// #7868: settled roots publish readable incomplete relations without stopping siblings.
// #7876: incomplete cache builds must not replay stale finding-free persisted results.
// #7509: source contexts resolve module-less relative Go imports.
// Quicksilver round 13 value_flow: caller-origin walks keep every alias path's
// evidence deficit, so type-flow call-location certainty changes for unchanged bytes.
// #7351: Go failure handlers decide error values and non-handlers by native method sets.
// #7886: native call evidence propagates nested budget and cancellation stops.
// #8036: retain native Go declared external receiver call identities.
// #7968: Go interface satisfaction decides members by the shared membership rule.
// #7509 G1b-1: native Go owners behind incomplete imports replace the legacy receiver answer.
// #7362: fixed JVM identities retain independent selected-environment scope.
// #6664: an incomplete descendant read leaves families and dispatch open instead of empty.
// #8153: overloads of one owner no longer prove an incoming call target, so the
// workspace oracle's incoming-actual substitution and reverse-caller reads change.
// #8000: selected external JVM on-demand candidates change type and member answers.
// #7509 G1b-2: native Go modeled callable results replace the legacy receiver answer.
// #6945: curated Python star imports can bind placed child modules and their calls.
// #7240: imported constructor receiver proofs change dispatch answers.
// #2445: an unsupported or incomplete external member family is an open
// hierarchy_unenumerated boundary, not a budget truncation, which changes dispatch boundary answers.
// #8264: predeclared Go modeled result types gain universe type identities.
// #7509 G1b-3 B: the Go pointer result-field proof reads the selected model callable;
// promoted fields and owners with unidentified promotion copies stay open.
// #8147 M4a: C# chains decided by file-local assignments or literal expressions change declarations and sites.
// #8290: a repeated read through one forward operation keeps the closed root's
// closure discharges, so warm binding answers become complete.
// #8167 S2/S5: authored supertype edges of a type without an owner declaration
// become positive widening witnesses, so overload applicability, selection and
// dispatch change on both routes.
// #8222: the Scala external-type ladder follows Scala's binding order and implicit
// roots, so legacy Scala type and boundary answers change.
// #8403: Rust reverse inventories ignore unrelated same-named calls of a different arity, so
// caller completeness and dispatch openness change.
// #8193: classify unenumerated dispatch separately from budget exhaustion.
// #8385: same-priority definition candidates in different files tie-break by source path, not absolute start byte.
// #7509 G1b-3 A: Go exact-binding result identity compares canonical native type digests.
// #8184/#8126: retained fills replay only their own reasons, so descendant fills no longer
// carry an enclosing query's gap and dispatch openness changes for unchanged bytes.
// #8191: retained fills in one request share one isolated cache domain.
// #8415: preserve enclosing JVM type parameters in external signatures.
// #8388: composition stops trusting Native caller authority; caller sets need complete inventory coverage.
// #8457: Rust trait-impl members reached through dispatch no named reverse row lists have open caller inventories.
// #8453: Go concrete methods reached through interface values have open caller inventories.
// #8546: a nested diff base could build its ICFG under the head's model hash; discard that window.
// #8402: Go artifacts come from parse-time rows, which can complete under a finite budget
// where on-demand lowering exceeded it.
// #8418/#8333: preserve positive external nominal closure targets (rung v288, above master v275 after batch #8529).
// #8579: Java, Kotlin and C# artifacts also come from parse-time rows.
// Batch 49878eab: combine #8579 with master (v303 vs v304); the two halves move together.
// #7750: Java procedures with a guarded switch lower instead of failing the switch contract.
// Batch 082b6a23: combine #8589 with the batch (v305 vs v306); the two halves move together.
// #8283: structural Go result proofs change exact-binding ICFG answers.
// Batch 082b6a23: combine #8594 with the batch (v307 vs v314); the two halves move together.
// #7509 G1b-3 F: Go nested-call result counts come from the native selected callable.
// Batch d1bb2a8e: combine #8517 with the batch (v315 vs v312); the two halves move together.
// #8602: relation axes and overwrite proofs discharge observer-free exceptional exits.
// Batch 1648c5ee: combine #8653 with the batch (v316 vs v318); the two halves move together.
// #8586: on-demand artifacts are lowered under the producer budget and admitted by census, so a
// finite request budget no longer decides completion differently by materialization route.
// Batch 1648c5ee: combine #8692 with the batch (v319 vs v322); the two halves move together.
// #8665: retain nonlocal Scala import qualifier boundaries in query-time ICFG answers.
// Batch 8efa980f: combine #8712 with the batch (v323 vs v330); the two halves move together.
// #7027 S2b-0: implicit JVM supertypes and closed intrinsic member inventories for
// kotlin.Any, kotlin.Annotation and Scala AnyRef change hierarchy and member answers (rung v308).
// #7027 S2b-0 r3: reserve v332 above master v315 for the validated root-owner read repair.
// #7027 S2b-0 merge2: coordinator reassigned v352 above master v331 and queued #8727 v333.
// #8516: package member provider targets change selected ICFG bindings; assigned above master v316/v315.
// Batch cb42f2c0: combine #8531 with the batch (v331 vs v338); the two halves move together.
// #8705: a Scala implicit root's own positive binding no longer discharges its open gap.
// Merge #8705 with master after #8712 (v332 vs v331); the two halves move together.
// Batch cb42f2c0: combine #8727 with the batch (v339 vs v333); the two halves move together.
// #8667: Go nested-call result counts that are unknown for a deterministic reason now carry a
// SemanticEvidenceGap, so call-shape completion changes; assigned above master v340/v339.
// #7509 G1b-3 G: a nested Go selector call whose receiver the source inference cannot type now
// takes its result count from the native selected callable; assigned above master v340/v339.
// Batch c1b44b74: combine #8667 (v364) with #7509 G1b-3 G (v366); the two halves move together.
// Batch 676be8c9: combine #7027 S2b-0 (v352) with master (v367); the two halves move together.
// #7960: a JavaScript call's thrown value now binds the enclosing catch parameter, so
// interprocedural exceptional flow changes; assigned above master v368/v367.
// Merge #8741 with master v368/v367; the two halves move together.
// Merge #8741 with master v376/v375 at the coordinator-assigned v384/v383; the two halves move together.
// #7619: parameterized JDK call results bind type-parameter-free receiver members.
// Coordinator reassigned the #7619 pair above master v439/v438.
// #8792: explicit Kotlin lambda parameters now publish lexical binders.
// Coordinator reassigned this pair to v402/v401 above master v376/v375.
// Batch 30414977: combine #8820 (v402) with master (v376); the two halves move together.
// #8836: revert #7960, so JavaScript call throws no longer bind catch parameters;
// assigned above master v376/v375 and every open pull request's pair (up to v388/v387).
// Batch 30414977: combine #8844 (v394) with #8820 (v403); the two halves move together.
// #7509 3a: Go call application roles come from selected native evidence, so a method expression
// on a parenthesized type operand is now Unknown; assigned above master v404/v403.
// #8872: preserve proven JS/TS package-module receiver identities across the
// available neutral gate; coordinator assigned v428/v427 above master v404/v403.
// #7509 5b step 1: Go source selector refinement takes owner, member, receiver preparation, field
// anchor and the interface trigger from selected native evidence; assigned above master v404/v403.
// Batch 66a984a8: combine #8881 (v428) with #8888 (v436); the two halves move together.
// Batch 66a984a8 promotion: combine master #8874 (v426) with this batch (v437); the two halves move together.
// #8388: Go builtin shadows can no longer refine an open ICFG snapshot to Complete;
// re-rung to v438 above master v426 and ready #8888 (v436).
// Batch c536ab7b: combine master (v438) with #8895 (v438); the two halves move together.
// Merge: combine #8888 (v436) with master #8874 (v426); the two halves move together.
// #7509 5b step 2: Go allocation dispatch narrowing takes the allocation type and member from
// selected native evidence; assigned above master v426/v425 and the reserved v438 and v440.
// Batch 7dd04e18: combine master (v439) with #8901 (v442); the two halves move together.
// #8823: retain binary JDK type-parameter scope in merged dependency packs; assigned above
// master v439/v438.
// Batch 7dd04e18 update: combine master #8823 (v462) with this batch (v443); the two halves move together.
// #8870: composed entry-point origins change policy answers;
// re-rung to v446 above master v439 and the ready and reserved pairs (up to v444).
// Batch 7880504b promotion: combine master (v463) with #8903 (v446); the two halves move together.
// #7509: a Go function-valued field call has no bound receiver; assigned above master
// v462/v461 and the open reservations.
// Batch 9dd7ee48: combine master (v464) with #8916 (v476); the two halves move together.
// #8866: Rust method receivers proven through ?, unwrap and expect on std Option/Result now bind modeled targets; coordinator-assigned v474/v473.
// Batch 7e70b7bc: combine master (v464) with #8866 (v474) and #8884 (v470); the two halves move together.
// #8884: Rust external receiver, member and type proofs read imports from the selected operation
// instead of live pooled imports; coordinator-assigned v470/v469 as conservative authority invalidation.
// Batch 7e70b7bc promotion: combine master (v477) with this batch (v475); the two halves move together.
// #8822: closed C# derivations remain resolved under an open compilation inventory; assigned
// above master v464/v463.
// Batch d50922f0: combine master (v477) with #8924 (v482); the two halves move together.
// #7509 5b step 3: Go nested-call result counts come from the selected native definition's
// signature instead of the legacy source inference; assigned above master and open reservations.
// Batch d50922f0: combine this batch (v483) with #8928 (v486); the two halves move together.
// Batch d50922f0 promotion: combine master (v478) with this batch (v487); the two halves move together.
// #8803: C# enclosing namespace scope selection changes resolved type and member answers.
// Coordinator reassigned the #7619 pair to v498/v497 above master v489/v488.
// #7509 G2: Go interface satisfaction proves slice, map and predeclared error signature
// identity, and shared projected shapes fold every node's completion; assigned above master.
// #7869: an unacquired JVM package provider is a per-reference obligation, and a targetless answer stays open (rung v480, coordinator).
// Batch 5aea0d33: combine master (v488) with #8679 (v480); the two halves move together.
// #8870: composed store ends change the workspace taint behavior identity;
// coordinator assigned v496/v495 above master v489/v488 and every reserved pair.
// Batch 8da812cd promotion: combine master (v490) with this batch (v496); the two halves move together.
// #8870: composed flow policies change endpoint inventory and candidate answers.
// Set to v506/v505, the coordinator's assignment above master v497/v496 and the open pairs through v504.
// Batch 5b711078: combine master and #7728 (v497, v498); the two halves move together.
// #8487: selected Java on-demand package outcomes reach the reference frame (rung v508, coordinator).
// #8992: glob admission requires a provider-declared owner before shadowing default gaps (rung v516, coordinator).
// Batch 5b711078: combine master and #8915 (v499, v516); the two halves move together.
// Batch 5b711078: combine master and #8973 (v504, v517); the two halves move together.
// Batch 6a13abe4 promotion: combine master (v518) with #8995 (v506); the two halves move together.
// #7804: Java expression chains take rooted package and type routes, and a targetless answer needs language-owned terminal proof to close; coordinator assigned v522 above master v518.
// Batch 565a8ef8: combine master (v519) with #7804 (v522); the two halves move together.
// Batch 7dcb059c: combine master (v523) with #9034 (v532); the two halves move together.
// #9063: a certified same-depth Go promotion collision leaves the method set, which changes satisfaction answers behind the native family and incoming-call recipients; coordinator assigned v540 above master v533.
// Batch 378fac65: combine master (v533) with #9063 (v540); the two halves move together.
// #9053: Go model-interface calls keep a reference receiver preparation and the declaring
// member's identity while dispatch stays open; set to v548 above master v541 and open pairs through v544.
// #8834: selected JVM root presence reads are verified before implicit-root answers are reused;
// coordinator assigned v514/v513 above master v497/v496 and every reserved pair.
// Coordinator re-assigned the #8834 pair to v524/v523 above master v518/v517.
// Coordinator re-assigned the #8834 pair to v542/v541 above master v533/v532 and the reserved pairs through v540.
// Coordinator re-assigned the #8834 pair to v550/v549 above master v548/v547 and the reserved pairs.
// Batch 02d43023 (#8834): combine v548 with v550; the two halves move together.
// #8811: closed relation discharges replay before a newly built request consumes its answer.
// Coordinator reassigned the #8811 pair to v494/v493 above master v489/v488.
// Coordinator reassigned the #8811 pair to v510/v509 above master v497/v496.
// Coordinator re-assigned the #8811 pair to v526/v525 above master v518/v517.
// Coordinator re-assigned the #8811 pair to v544/v543 above master v533/v532 and the reserved pairs through v540.
// Coordinator re-assigned the #8946 pair to v552/v551 above master v548/v547 and the reserved pairs.
// Batch 02d43023 (#8946): combine v551 with v552; the two halves move together.
// #9101: member selection on a model-declared Go interface no longer marks the promotion
// frontier unavailable; coordinator assigned v558 above master v548.
// Batch e4fc49ee (#9101): combine master v553 with #9101 v558 as max + 1; the two halves move together.
// #9050: Rust type lookup answers model-declared external types, and an unprojectable external type identity no longer makes the type operation unavailable, which changes resolved type and member answers; coordinator assigned v550 above master v541.
// Merge for #9050: combine master (v548) with #9050 (v550); the two halves move together.
// Merge for #9050: combine master (v553) with #9050 (v551); the two halves move together.
// Merge for #9050: combine master (v559) with #9050 (v554); the two halves move together.
// #8929 (#8896): member reads cross content-preserving argument copies in call plans;
// coordinator assigned v562/v561 above master v560/v559 and every reserved pair.
// #9196: invocation, root and capture admission, plus Rust local-closure dispatch,
// change selected ICFG answers; coordinator assigned the paired v566/v565 domains.
// #9060: typed-round call-result forwarding can complete a formerly budget-limited root;
// coordinator assigned v568/v567, above #9196's v566/v565 on master.
// #9195: native Scala follows selected source alias parents, changing member-family
// ancestry, descendants, virtual dispatch, and ICFG answers; paired v572/v571.
// #9220: renamed object-member imports (Scala {x => y}, Kotlin as) now resolve
// through the authored member; Scala and default-build Kotlin answers change.
// Coordinator assigned v578/v577 as the paired provider behavior domains.
// #6291: native Java claims an import boundary only for an explicit single-type
// import. The receiver status reaches CallDispatchLookup.boundary and then
// WorkspaceIcfgProvider call transfers; UnresolvableImportBoundary was eligible
// for exhaustive dispatch while Incomplete stays open. Paired v582/v581.
// #6792: bare Scala method values and certified term-family binding change
// workspace call and member targets; v590 is the coordinator-assigned pair.
// #9194: local_type_binding reaches call diagnostic kinds and the Unproven
// boundary proof in workspace_oracle/dispatch.rs; provider answers change.
// #9194: Coordinator assigned v588/v587 above master v582/v581.
// Merge of #9194 with #6792 (v588 and v590): max + 1 gives v591/v590.
// #7654: native Scala AnyRef member dispatch reaches WorkspaceIcfgProvider
// independently of RQL; coordinator assigned full v598 and read v597.
// #7509: the sole-spec Go alias bridge reaches Go point and receiver selected
// declaration reads through WorkspaceIcfgProvider -> dispatch -> CallRelationService.
// #9195: exact Scala reference package contexts change selected hierarchy reads;
// coordinator assigned v608/v607 above master v604/v603 (v600/v599 retired).
// #9323: Kotlin and Scala `java.lang` value names close under a selected JDK and
// Kotlin static JDK calls select their member; v616 above master v604.
// Batch merge of #9195 (v608) and #9323 (v616): max + 1 = v617.
// #7726: Kotlin native points carry the selected external call proof into
// dispatch, which keys it under the callee's declaring language; v618, and
// merged with master's v617: max + 1 = v619.
// #8307: a C# member name inside an element access (`request.Query["x"]`)
// resolves to the member instead of the indexer; v622 above master v617 and
// the open pairs through v618.
// Batch merge of #9414 (v622) and the batch (v619): max + 1 = v623.
// #8826: limited C# global-using calls no longer seed full cells, changing
// alias-dependent dispatch targets; v606/v605 retired after master reached v617/v616,
// coordinator assigned full v620 and read v619.
// Batch merge of #8826 (v620) and master (v623): max + 1 = v624.
// #9277: Go reconciliation uses the selected session source/configuration
// snapshot. Coordinator assigned replacement full v618 and read v617.
// Batch merge of #9344 (v618) and the batch (v624): max + 1 = v625.
// #7960: a JavaScript call's thrown value binds the catch parameter again, and
// a field read through a binder several copies define is resolved per
// definition; v620 is above every open pull request's pair (highest v616).
// Merge of #7960 (v620) with master (v617): max + 1 = v621.
// Batch merge of #9413 (v621) and the batch (v625): max + 1 = v626.
// #9336: a Ruby singleton call on a model-declared constant no longer carries
// its exact external proof when the caller's file rewrites the called method,
// which changes its dispatch answer; v622 above master v617.
// Batch merge of #9425 (v622) and the batch (v626): max + 1 = v627.
// #9336 follow-up: a rewrite of that singleton method in any other workspace
// file also keeps the call open; v624 above #9336's v622.
// Batch merge of #9429 (v624) and the batch (v627): max + 1 = v628.
// #9378: indexed modeled call results get their complete modeled identity, so
// WorkspaceIcfgProvider heap answers change. The coordinator first assigned
// v624/v623; #9429 independently used v624/v623, so it reassigned full v636
// and read v635 above master v623/v622 (v624/v623 retired for #9404).
// Batch merge of #9404 (v636) and the batch (v628): max + 1 = v637.
// #9323: Kotlin constructor callees take the imported JDK type and expand to its
// constructors; v621 above #7726's v619.
// Batch merge of #9323 (v621) and master (v624): max + 1 = v625.
// Batch merge of #9422 (v625) and the batch (v637): max + 1 = v638.
// #9378 S2: Go receiver-owner relations and pointer argument and receiver
// handoffs change selected dispatch and value-flow answers that
// WorkspaceIcfgProvider reads; coordinator assigned v632/v631.
// Batch merge of #9426 (v632) and the batch (v638): max + 1 = v639.
// #7509: directional Go channel identities change selected method signatures;
// v634 invalidated full provider and dispatch answers; v634/v633 were retired
// after master reached v639/v638, and the coordinator assigned full v640 and read v639.
// #9322: a Ruby block parameter takes the class its callee yields, so calls on
// it gain targets; v634 above master v628, clear of concurrent Ruby/PHP lanes.
// Merge of #9322 (v634) with master (v639): max + 1 = v640.
// Merge of #9322 (v640) with master (v640): max + 1 = v641.
// #9324: Scala JDK calls and external constructor references gain proven
// dispatch targets; v642 above master v640.
// Merge of #9324 (v642) with master (v641): max + 1 = v643.
// #9438: decorator argument edges reach semantic-model overlay rules and captures;
// the provider's full behavior identity changes. v643/v642 were retired after
// #9468 took the same pair; the coordinator assigned full v646 and read v645.
// Merge of #9438 (v646) with master (v643): max + 1 = v647.
// #9060: semi-naive typed rounds re-evaluate only dirty references and slots,
// so references that stopped at the same budget can now complete. Coordinator
// first held v602/v601 (retired below master v617/v616);
// coordinator reassigned full v622 and read v621 above master v617/v616;
// #9414 independently used v622/v621, so the coordinator reassigned full v628
// and read v627 (v622/v621 retired for #9300).
// #9300 (#9060) merged with master v641/v640: v628/v627 retired below master;
// the coordinator assigned full v648 and read v647 above the held pairs.
// Merge of #9300 with master v643/v642 (#9324): the coordinator-assigned v648/v647
// stays strictly above master.
// Merge of #9300 with master v647/v646 (#9438): the coordinator-assigned v648/v647
// stays strictly above master.
// #9002: a JVM qualified-name continuation now carries its head's open lexical-choice
// reasons, so selected call and dispatch answers that WorkspaceIcfgProvider reads change;
// the coordinator assigned full v645 and read v644.
// Merge of #9002 (v645) with master (v647): the coordinator assigned full v651 and read
// v650, retiring v645/v644.
// #9532: Java external calls admit proofs over formals with unproven type
// arguments, changing retained call-binding answers; v653 above master v648
// and open #9483's v651.
// #5658: Python product surfaces answer from the native engine (with the shared hierarchy-order
// session axis and completed-root refusals); coordinator assigned v657/v656 above master v653/v652
// and every reserved pair (the earlier v520/v519, v536/v535, v554/v553, v570/v569, v584/v583,
// v630/v629, v644/v643 and v650/v649 assignments were retired when master or another open pull
// request took them).
// #9447: formal values, unavailable layout/capture proofs, and stable local Go
// function-literal targets/captures change selected call transfers; v649/v648
// replaces the pair overtaken by master v647/v646.
// #9447: the assigned pair remains above merged master v648/v647.
// #9532: Java external calls admit proofs over formals with unproven type
// arguments, changing retained call-binding answers; v653 above master v648
// and open #9483's v651.
// The same unpublished epoch covers declared Go application-result obligations
// joined to the existing exact source-call certificate, separately from body types.
// #9447: merge with master v653/v652 takes max of each side plus one;
// the coordinator-assigned full v654/read v653 replaces v649/v648.
// #9447: merge with master v657/v656 takes max of each parent plus one,
// producing full v658/read v657 before the separately assigned identity carry.
// #9447: the coordinator renews the unpublished pair to full v660/read v659
// above master v657/v656 and distinct from the held v658 and v659 full domains.
// #9183: v661/v660 assigned by the coordinator (2026-11-04), above master v657/v656 and #9447's reserved v660/v659.
// #9522: receiver Incomplete candidates change open dispatch and coverage answers;
// coordinator assigned v659/v658 above master v657/v656 (v653 and v656 retired).
// #9557: native member families name certified unread ancestors and language roots,
// changing hierarchy answers that ICFG consumers read; coordinator assigned v662/v661
// above master v657/v656; merged with master's #9522 v659/v658, v663 = max + 1.
// #8675 S2: proven Java Type-frontier gap occurrences change answers; coordinator assigned
// v665/v664 above master v663/v662 (v652 and v658 retired).
// #9183: the coordinator renews the unpublished pair to full v668/read v667 (2026-11-04),
// above master v663/v662 (#9557) and the reserved v665-v667 pairs.
// #9575: selected Python resolution and graph routes can change retained semantic-provider and
// policy answers; coordinator assigned v663/v662 above v657/v656.
// #9575 master merge: both full domains were v663; max + 1 = v664.
// #9575: coordinator renewed the unlanded repair to v666/v665 above master v663/v662
// and the held pairs; v663/v662 and the intermediate merge pair are retired.
// #9575/#8675 S2 merge: full v667 = max(v666, v665) + 1; read v666 pairs with it.
// #9575 coordinator renewal: full v671 is above the current v667 ladder; prior pairs retired.
// #9546 M1a: shape (c) member prefixes drop from a selected boundary to Truncated dispatch;
// coordinator assigned v669/v668, above master v665/v664 after #8675 S2 landed.
// #9575 final coordinator renewal: v675/v674 follows required master composition above
// the #8837 v674/v673 hold; v671/v670 and the conflict pair v672/v671 are retired.
// #9447: importing #9575 takes max(v660, v675) + 1; the coordinator assigned
// full v676/read v675 for this unpublished composed change.
// #9183: coordinator renewal for the #9547 dependency import, full v679/read v678 (2026-11-04).
// #9563: semi-naive typed rounds keep the query obligations held by a clean reference's owned and
// read query nodes; the published-union filter can change a selected answer's completion, which the
// callee lookup carries into workspace dispatch and ICFG call-binding completeness. The coordinator
// assigned full v670 and read v669.
// #9183: coordinator renewal for the #9547 dependency import, full v679/read v678 (2026-11-04).
// #9575 final coordinator renewal: v675/v674 follows required master composition above
// the #8837 v674/v673 hold; v671/v670 and the conflict pair v672/v671 are retired.
// #9563/#9575 merge: full v676 = max(v670, v675) + 1; read v675 pairs with it.
// #9447: importing #9575 takes max(v660, v675) + 1; the coordinator assigned
// full v676/read v675 for this unpublished composed change.
// #9447 queue correction: merging master e19802c7 requires at least max(676, 670) + 1.
// The coordinator assigned distinct full v680/read v679 above the occupied and held pairs;
// the prior unpublished v676/v675 pair is retired for this corrected composition.
// #9447 landed-prerequisite merge: max(680, 676) + 1 is the conflict minimum.
// The coordinator renewed this unpublished composition to distinct full v683/read v682;
// v680/v679 is retired, with the dependent change reserved above this pair.
// #9183: corrected #9547 dependency import renews full v684/read v683 above v683/v682.
// Merge of #9002 with #9563 (v670) and master v669: the coordinator assigned full v678 and
// read v677 for the combined head, retiring v651/v650.
// Merge of #9002 (v678) with master v676: the literals conflicted, so under max + 1 the
// coordinator assigned full v685 and read v684, retiring v678/v677 (v679-v684 were held).
// Batch merge of #9002 (v685) with master v683 (#9447): max(683, 685) + 1 gives full v686.
// #8837: present empty Directory.Build/Packages files and absent GetPathOfFileAbove
// probes change C# membership; all-present byte-identical workspaces retain content identity.
// #8837 coordinator renewal after #9575: full v682 / read v681 above master v676/v675;
// v674/v673 is retired for the new composition.
// #8837 coordinator renewal at the master 7dddaf240f merge: full v688 / read v687 above
// master v686/v685 and every open pair; v682/v681 is retired.
// #9183 renewal above master v686: this composition uses v687.
// Batch merge of #9183 (v687) with master v688 (#8837): max(688, 687) + 1 gives full v689.
// #9779: C++ macro-recovery owners bind no lexical parameters, and proven recovered
// Blocks/braced-default formals publish signatures again; full v689 is above master
// v686 and the open #9579 (v687) and #9723 (v688) pairs.
// Batch merge of #9779 (v689) with master v688 (#8837): max(688, 689) + 1 gives full v690.
// Merge of master v690 (#9779) into the #9183 batch (v689): max(690, 689) + 1 gives full v691.
// #9835: sparse Rust generic formals instantiate selected call results by ordinal.
// #9784: stored semantic IR publication reads join the provider read set; full v693 (coordinator-assigned, above master v691).
// #8500: certified external-owner targets change selected call production and completion
// (owner-only answers take the targetless call-inventory branches); the coordinator assigned
// full v691 and read v690 over master v686/v685.
// #8500 coordinator renewal at the master 3914f71ed2 merge: full v694 / read v693 above master
// v691/v690 and the held #9550 (v692) and #9784 (v693) pairs; v691/v690 is retired for #8500.
// #9784: coordinator renewal: full v698 / read v697 above master v696/v695 (#9550) and the held #9835 (v697/v696).
// #9550: coordinator allocation full v689 above #9579 full v687 and master v686.
// #9550: current-master composition uses coordinator-assigned full v692.
// #9550: coordinator renewal at the master 1de0d3baf1 composition (b13acf4d44): full v696 / read v695
// above master v694/v693 and the held #9835 (v695/v694); v692/v691 is retired for #9550.
// #9651: exact stores through unrebound formals kill earlier member values; merging
// master v696/v695 takes max + 1, and full v699 / read v698 also clears the open
// #9856 pair (v697); v677/v676 is retired.
// #9835: the merge with #8500 conflicted on this pair, so the coordinator renewed it to full
// v697 / read v696 (v695/v694 retired; v696/v695 is held by #9550).
// #9835: the merge of master 044662f15e (#9550 at full v696 / read v695) conflicted again, so the
// coordinator renewed this change to full v700 / read v699; v697/v696 is retired (v699/v698 is #9702).
// Batch merge of #9856: max of both sides + 1 gives full v701 / read v700.
// Batch merge of #9910: max of both sides + 1 gives full v702 / read v701.
// #9783: an explicit single-type import of a pack-declared type admits its owner and
// removes that route's proved unsupported-route reasons; the changed completion reaches
// qualified member lookup through constructor qualifiers. The coordinator assigned full
// v702 / read v701 above master v696/v695 and the held pairs through v701/v700.
// #9783: master 760c5166d7 reached v702/v701 (#9910), so the coordinator renewed this change
// to full v704 / read v703; v702/v701 is retired for #9783 (v703/v702 is held by #9840).
// #9840: the dependency-discovery evidence output digest joins both provider
// halves; coordinator allocation full v703 / read v702 above master v696/v695.
// #9840: the merge of master ff83fe24db (full v702 / read v701) conflicted on both literals, so the
// coordinator renewed this change to full v705 / read v704; v703/v702 is retired (v704/v703 is #9783).
// Batch merge of #9840: max of both sides + 1 gives full v706 / read v705.
// #9852: coordinator allocation full v701 / read v700 above master v696/v695 and the held
// #9702 (v699/v698), #9835 (v700/v699) and #9784 (v698/v697) pairs: Go signature comparisons
// count an external type leaf only when the current close attempt certifies its owner.
// #9852: the merge of master 8d2800ded9 (v702/v701) conflicted on this pair; max of both
// sides + 1 gives full v703 / read v702, pending the coordinator's renewal.
// #9852: coordinator renewal at that merge: full v706 / read v705 above master v702/v701 and the
// held #9783 (v704/v703) and #9840 (v705/v704) pairs; v703/v702 is retired for #9840, and
// v701/v700 is retired for #9852.
// Batch merge of #9852: both sides reached full v706 / read v705; max of both sides + 1 gives full v707 / read v706.
// #9900: Java member-family edges compare erased parameter types instead of arity, so a
// same-arity overload no longer reads as an override; full v697 is above master v696.
// Merge of master v702 (#9910) into #9900 (v697): max(702, 697) + 1 gives full v703.
// Batch merge of #9939: max of both sides + 1 gives full v708 / read v707.
// #9677: a Kotlin class-name receiver bound only by an explicit import selects its
// external member again; full v703 / read v702 above master v702/v701.
// Batch merge of #10016: max of both sides + 1 gives full v709 / read v708.
// #9324: an external overload that call applicability rejects no longer opens an
// access gap, so retained JVM call answers change; full v703 above master v702.
// Merge of #9324 (full v703) with master v707/v706: max of both sides + 1 gives full v708 / read v707.
// Batch merge of #10024: both sides reached full v709 / read v708 and v708 / v707; max of both sides + 1 gives full v710 / read v709.
// #7708: call arguments carry their declared type arguments and same-owner wildcard containment
// decides overloads. The native-engine reviewer assigned full v711 / read v710 above master v709/v708
// and #10021's v710/v709.
// #9479: Scala parameterless selections become dispatch sites; full v703 / read v702.
// Merge of #9479 (full v703) with master v710/v709: max of both sides + 1 gives full v711 / read v710.
// #9423: full v708 / read v707 above master v707/v706: the shared JVM subtype walk reads extracted
// supertype targets, array formals refute non-array classes, and Kotlin default-import callees
// take the JDK type, so Kotlin and Scala JDK overload answers change for unchanged bytes.
// Merge of master v710/v709 (#10024) into #9423 (v708/v707): max of both sides + 1 gives full v711 / read v710.
// Batch merge of #9479 (full v711 / read v710) with #9423 (full v711 / read v710): max of both sides + 1 gives full v712 / read v711.
// #10021: a creation's type completion follows its type qualifier, not its constructor's
// overload selection, so receivers of `new T(...)` gain their type. The native-engine reviewer
// assigned full v710 / read v709 above master v709/v708.
// #10021: #10024 landed at full v710 / read v709, so the reviewer renewed this change to full
// v712 / read v711 above it (v711/v710 is held by #7708); v710/v709 is retired for #10021.
// Batch merge of integrated full v712 with #10021 full v712: max of both sides + 1 gives full v713 / read v712.
// Merge of master full v713 / read v712 with #7708 full v711 / read v710: max of both sides + 1 gives full v714 / read v713.
// #9766: separated value-copy alternatives change provider member relations consumed by persisted dynamic field-slot surveys.
// #9324: full v715 / read v714 above master v714/v713: Scala call applicability proves and
// refutes reference conversions through the closed JVM hierarchy, so a refuted overload is
// inapplicable and Scala JDK overload answers change for unchanged bytes.
// Merge of master full v715 / read v714 (#9766) with #9324 full v715 / read v714:
// max of both sides + 1 gives full v716 / read v715.
// #9995: full v717 / read v716 above master v716/v715 and #9324's v715/v714: Scala `T(args)` on a
// selected JVM external owner applies its static `apply` family, Scala's intrinsic `String` compares
// as the JDK class, a known-head external formal refutes by its head, and a rejected candidate's
// own signature gaps no longer reach the call, so Scala library call answers change for unchanged bytes.
// Merge of #9995 (full v717) with master full v716: max of both sides + 1 gives full v718.
// #5658 M8 step 1a: Python definition dispatch and value identity answer from the native
// selected resolution, and the workspace oracle's Python call targets now come from the
// native definition batch resolver, so retained Python dispatch answers change for
// unchanged bytes; full v713 / read v712, reserved by the coordinator above master v710/v709.
// #5658 M8 step 1a: master reached full v713 / read v712 in #10211, equal to this pair, so the
// coordinator renewed it to full v723 / read v722 (v714/v713 is held by #10182).
// Merge of master full v714 / read v713 (#7708) into #5658 M8 step 1a (full v723 / read v722): the
// coordinator-allocated pair stays, above master.
// #5658 M8 step 1a: the merge of master v714/v713 and then v718/v717 conflicted in these literals after
// v723/v722 was pushed, so the coordinator allocated a fresh pair for the merged tree: full v724 / read v723.
// #9423: a Kotlin property read selects a Java getter of an external JVM owner by its
// synthetic property name and carries its exact call proof, so Kotlin dispatch and
// call-target answers change for unchanged bytes.
// Merge of master full v724 with #9423 full v719: max of both sides + 1 gives full v725.
// #5658 M8 P1: a proven classmethod receiver discharges its parameter's unannotated gap, so
// Python definitions, dispatch and class candidates through `cls` change for unchanged bytes;
// full v733 / read v732, allocated by the coordinator above master v725/v724 and open heads.
// #10385: a package-private or protected external JVM member that the caller provably
// cannot access is no longer an access gap, so member and dispatch answers that named
// one (Kotlin `entry.name` beside `ZipEntry.name`) change for unchanged bytes.
// Merge of master full v733 / read v732 with #10385 full v726 / read v725:
// max of both sides + 1 gives full v734 / read v733.
// #5658 M8 P2: subscripted and union annotations name their outer class or members, so
// Python definitions, dispatch and class candidates through annotated values change for
// unchanged bytes; full v734 / read v733, allocated by the coordinator above P1's v733/v732.
// Merge of master full v733 (#10407) into P2: the allocated pair stays, above master.
// #5658 M8 P2: master reached full v734 / read v733 through #10385, equal to this pair, so
// the coordinator renewed it to full v735 / read v734.
// #8675 S3 (#9324): a Scala term-path head keeps lexical lookup and sees the file's imports,
// a qualified route selects an external JVM member at its terminal, and a decided qualified
// member retires its own qualified-type gap on its value slot, so Scala `Owner.MEMBER`
// reads and the overload calls that take them change for unchanged bytes; full v726 above
// master v725.
// Merge of master full v735 with #8675 S3 full v726: max of both sides + 1 gives full v736.
// #10388: the JVM external index no longer replays declaration-scoped producer warnings as
// query-wide incompleteness, so reads over unchanged dependency jars change completeness;
// full v726 / read v725.
// Merge of master full v735 / read v734 with #10388 full v726 / read v725:
// max of both sides + 1 gives full v736 / read v735.
// Merge of master full v736 / read v735 with #10388 full v736 / read v735:
// max of both sides + 1 gives full v737 / read v736.
// #7643: a parameterized actual is projected onto a different generic owner through its declared
// supertype path before containment decides overloads. The native-engine reviewer assigned full
// v720 / read v719, renewed it to v726/v725 and then v739/v738 after master merges, and allocated
// full v742 / read v741 for the tree that merges master v736/v735 before Ready.
// Merge of master full v737 / read v736 with #7643 full v742 / read v741:
// max of both sides + 1 gives full v743 / read v742.
// #10445: Scala parameter bindings activate after their own clause, so resolution
// and dispatch answers change for unchanged bytes; rotate both halves together.
// #5658 M8 P3: a Python call's callee carries only the callable result, so Python definitions,
// dispatch proofs and type answers through method calls change for unchanged bytes; full v748 /
// read v747, allocated by the coordinator above master v743/v742 and the reserved v744-v747.
// #5658 M8 P3: the merge of master full v744 / read v743 (#10445) conflicted with v748/v747 before
// the pair was pushed, so the coordinator allocated a fresh pair for the merged tree: full v751 /
// read v750.
// #9224: coordinator allocation full v714 / read v713 above master v710/v709 and the held #7708
// (v711/v710), #10021 (v712/v711) and #5658 step 1a (v713/v712) pairs: the target-keyed Go match
// changes selected reverse and incoming-call answers for unchanged bytes.
// #9224: coordinator renewal full v725 / read v724 above master v718/v717 and the held v719-v724,
// after the rejected head's v714/v713 was superseded.
// #9224: the merge of master 0a31363d8e (v724/v723) conflicted on these literals after v725/v724
// was pushed; the coordinator allocates a fresh pair for the merged tree.
// #9224: coordinator fresh pair full v731 / read v730 for the merged tree, above master v725/v724
// (#9423 took 725, which collided with this PR's pushed pair) and the held v726-v730.
// #9224: master f1a9aeef10 reached v734/v733, above this PR's pushed v731/v730, so the coordinator
// allocated a fresh pair for the merged tree: full v737 / read v736.
// #9224: #10427 pushed full v737, the pair this PR held unpushed, so the coordinator re-allocated
// a fresh pair for the merged tree above master v736/v735: full v744 / read v743.
// #9224: #10454 pushed full v744, the pair this PR held unpushed, so the coordinator re-allocated
// a fresh pair for the merged tree above master v743/v742: full v749 / read v748.
// #9224: master 6923d41cab reached v751/v750, above this PR's unpushed v749/v748, so the coordinator
// allocated a fresh pair for the merged tree: full v753 / read v752.
// #10106: coordinator allocation full v717 / read v716 above #10146's v714/v713 and the
// conditional #9766 (v715/v714) and #10045 (v716/v715) reservations: a written Go type that
// no active declaration provider supplies stays open instead of completing empty.
// #10106: coordinator renewal full v732 / read v731 after merging #9224 full v731 / read v730.
// #10106: master reached v734/v733, so the coordinator allocated a fresh pair above #10146's
// v737/v736: full v738 / read v737.
// #10106: #10427 pushed v737, so the coordinator re-allocated #10146 to v744/v743 and this PR
// to the pair above it: full v745 / read v744.
// #10106: #10454 pushed v744, so the coordinator re-allocated #10146 to v749/v748 and this PR
// to the pair above it: full v750 / read v749.
// #10106: master reached v751/v750, so the coordinator allocated #10146 v753/v752 and this PR the
// pair above it: full v754 / read v753.
// #5658 M8 P5: a one-hop module alias qualifier is a namespace, so Python class-set roots and
// call targets change; coordinator fresh pair above master v753/v752: full v758 / read v757.
// #5658 M8 P5: v758 was pushed before a conflicting master merge, so the coordinator allocated a
// fresh pair for the merged tree above master v754/v753: full v760 / read v759.
// #10020: a Scala or Kotlin member-selection leaf no longer binds the same-named local being
// declared, so definition and call-target answers change for unchanged bytes: full v755 /
// read v754.
// #10020: master reached v760/v759 (#5658 M8 P5), so the merge takes max + 1: full v761 /
// read v760.
// #5658 M8 P4: a qualified nested class definition reports its identity, so Python class-set roots
// and call targets change; coordinator fresh pair above master v754/v753: full v760 / read v759.
// #5658 M8 P4: the coordinator gave v760/v759 to the module-alias PR, which lands first, and moved
// this unpushed PR to the pair above it: full v761 / read v760.
// #5658 M8 P4: master reached v761/v760 (#10020), so the coordinator allocated a fresh pair for
// the merged tree: full v762 / read v761.
// #7860: a native Java receiver's type arguments are substituted into the selected external
// member's formals and return type. The native-engine reviewer renewed its pair after each
// conflicting merge (v722, v727, v740, v743, v746, v755); master reached v761/v760 before this
// merge, so it allocated full v765 / read v764.
// Merge of master full v762 / read v761 with #7860 full v765 / read 764:
// max of both sides + 1 gives full v766 / read v765.
// #10466: a rejected return member is a content gap (coverage Open), not a capacity
// truncation, so value-flow snapshot coverage changes for unchanged bytes; the
// identity reviewer assigned full v757 / read v756.
// #10466: master reached v761/v760 (#10020 after #5658 M8 P5), so the identity reviewer
// renewed the pair: full v763 / read v762.
// #10466: master reached v766/v765 (#10532), so the identity reviewer renewed the pair:
// full v768 / read v767.
// #10526: full v767 / read v766; a Go keyed-literal label whose source-less
// owner type is unprovided reports go_literal_owner_unresolved again.
// Merge of master full v768 / read v767 with #10526 full v767 / read v766:
// #10000: an external Java constructor family that arity alone does not select binds its
// overload from argument types instead of resolving to a target-free type boundary; above
// master v766/v765: full v767 / read v766.
// Merge of master full v768 / read v767 with #10000 full v767 / read v766:
// both merges give full v769 / read v768.
// This integration merge combines master full v769 / read v768 with #10000 full v769 /
// read v768: max of both sides + 1 gives full v770 / read v769.
// #7860 slice 2 A: a native Java external method whose name a field shares keeps its
// member identity, so its declared result types enclosing calls; above master v770/v769:
// full v771 / read v770.
// #9869: a Go call in a build-constrained file of a source-inventory package (failed or
// disabled discovery) is no longer a complete binding; above master v771/v770: full v772 /
// read v771.
// #10432: native Java call-row conversions are proven against the selection's type-argument
// bindings, so retained conversion and binding answers change; above master v772/v771:
// full v773 / read v772.
// #5658 M8 Python native type switch: type flow takes native Python type answers, so class-set
// roots, field slots and call targets change.
// This integration merge combines master full v773 / read v772 with #10653 full v773 /
// read v772: max of both sides + 1 gives full v774 / read v773.
// #9332: a call that omits formals with published saved defaults is a complete
// binding; above master v774/v773: full v775 / read v774.
// #10563: a read that continues through a cell a reference was stored into follows the
// stored object, and a store the resolver cannot follow makes the read partial; above
// master full v775 / read v774 (#9332) and #10685 full v775 / read v774: full v776 / read v775.
// #10582: Go interface argument conversions separate copied values; above master full
// v774 / read v773: full v775 / read v774.
// #10689: rank semantic model evidence within each language family.
// This integration merge combines full v777 / read v776 with the batch's #10563
// full v776 / read v775: max of both sides + 1 gives full v778 / read v777.
// This integration merge combines full v776 / read v775 with #10689 full v775 /
// read v774: max of both sides + 1 gives full v777 / read v776.
// #10052: Fenced pack family dispositions change C# external call dispatch through `member_is_static`
// (csharp external.rs -> `csharp_normalized_static_owner` in call_relations.rs -> the workspace-oracle
// dispatch); the coordinator allocated full v729 / read v728, above master v724 / v723.
// Merge of master full v734 / read v733 with #10052 M2 full v729 / read v728: v729 is below master,
// so the coordinator allocated a fresh full v736 / read v735.
// Merge of master full v754 / read v753 with #10052 M2 full v736 / read v735: v736 is below master,
// so the coordinator allocated a fresh full v759 / read v758.
// #10052 M2 under the 2026-11-07 lever rule: master and #10589 are at full v770 / read v769, so M2 takes
// #10052 M2 final merge under the 2026-11-07 lever rule: master is at full v774 / read v773,
// so M2 takes full v775 / read v774.
// #10052 M2 final merge (2026-11-08): master is at full v777 / read v776, so M2 takes
// full v778 / read v777.
// #10052 M2 final merge (2026-11-08 11:25Z): master reached full v778 / read v777, so M2
// takes full v779 / read v778.
// #8804: a call's exceptional continuation relays its thrown value to the caller's
// exceptional-return port; above master v775/v774: full v776 / read v775.
// Merge of master full v778 / read v777 with #8804 full v776 / read v775: max of both
// sides + 1 gives full v779 / read v778.
// Promotion merge of master #8804 full v779 / read v778 with the batch's #10052
// full v779 / read v778: max of both sides + 1 gives full v780 / read v779.
// #7314 AD3d: C# compilation membership changes for unchanged inputs and no ICFG
// input folds it. Merged with master full v779 / read v778: max of both sides + 1
// gives full v780 / read v779.
// Merge of master full v780 / read v779 from the #10827 batch with #7314 AD3d
// #10683: an identity prefix store no longer redirects a longer access, so truncated
// value-flow snapshots complete; above master full v779 / read v778: full v780 / read v779.
// Promotion merge of master full v780 / read v779 with the batch's #10683
// full v780 / read v779: max of both sides + 1 gives full v781 / read v780.
// #10812: Java model overloads are selected by the actuals' types, and a zero-argument
// source call actual is typed by its declared return, so retained conversion and binding
// answers change; above master v781/v780: full v782 / read v781.
// Promotion merge with master bb6a872a full v781 / read v780 and this branch's
// full v781 / read v780: max of both sides + 1 gives full v782 / read v781.
// Promotion merge with master full v782 / read v781 and this batch's
// full v782 / read v781: max of both sides + 1 gives full v783 / read v782.
// #10357: selected file-program evidence opens otherwise empty C# membership; above master full v783 / read v782: full v784 / read v783.
// #10356: derived Razor SDK projects inherit default Compile membership; above master full v784 / read v783 (#10357): full v785 / read v784.
// Merge of master full v784 / read v783 (#10357) with this branch's full v785 / read v784: max of both sides + 1, past the open #7314 pairs, gives full v788 / read v787.
// #10687 B: a Rust argument conversion that may run a user Deref weakens the call's
// transfer; above master full v779 / read v778: full v780 / read v779.
// Merge of master full v780 / read v779 with #10687 B full v780 / read v779: max of
// both sides + 1 gives full v781 / read v780.
// Merge of master full v782 / read v781 with #10687 B full v781 / read v780: max of
// both sides + 1 gives full v783 / read v782.
// Merge of master full v783 / read v782 with #10687 B full v783 / read v782: max of both
// sides + 1 gives full v784 / read v783.
// Merge of master full v788 / read v787 with #10687 B full v784 / read v783:
// max of both sides + 1 gives full v789 / read v788.
// #7314 AD3d EC2 r5: three-valued MSBuild conditions change C# membership answers; above master full v784 / read v783: full v786 / read v785.
// Merge of master full v784 / read v783 (#10357) with this branch's full v786 / read v785: max of both sides + 1, past the open #7314 pairs, gives full v789 / read v788.
// Merge of this batch's full v789 / read v788 with #7314 AD3d full v789 / read v788:
// max of both sides + 1 gives full v790 / read v789.
// #8430: grammar 0.23.9 parses namespace-body extern aliases as directives; above master full v784 / read v783: full v787 / read v786.
// Merge of master full v784 / read v783 (#10357) with this branch's full v787 / read v786: max of both sides + 1, past the open #7314 pairs, gives full v790 / read v789.
// Merge of this batch's full v790 / read v789 with #8430 full v790 / read v789:
// max of both sides + 1 gives full v791 / read v790.
// #10770 slice 1: Rust non-generic method results and primitive operator results
// get exact types, so fewer argument conversions stay may-run-user-code and
// retained call transfers change: full v792 / read v791.
// #7314 M10a0: named-open configuration symbols change branch decisions; full 797/read 796.
// #10761: an uncertified external overload family binds its known members as a
// possible identity instead of Conflict/incomplete, so retained call-binding
// answers change; above master v784/v783: full v785 / read v784.
// Merge of master full v788 / read v787 with #10761's full v785 / read v784:
// max of both sides + 1 gives full v789 / read v788.
// #10884: a Java model overload family selects its most specific applicable
// overload, and a reference actual is rejected for a primitive formal, so
// retained binding answers change. Merge of master full v788 / read v787 with
// this branch's full v785 / read v784: max of both sides + 1 gives full v789 / read v788.
// Merge of the batch's #10761 full v789 / read v788 with #10884 full v789 / read v788:
// max of both sides + 1 gives full v790 / read v789.
// Merge of master full v791 / read v790 with the batch's full v790 / read v789:
// max of both sides + 1 gives full v792 / read v791.
// Combined with other active #7314 lanes and current master: full v806/read v805.
// Promotion merge of this batch's full v792 / read v791 with master's
// #10761/#10884 full v792 / read v791: max of both sides + 1 gives full v793 / read v792.
// #10802: log macro arguments are proven only for the real log package, and an
// unknown macro argument list now fails closed: full v794 / read v793.
// Rust std Deref receiver chains consume exact complete summaries at query time.
// Merge above master full v793 / read v792 gives full v794 / read v793.
// #10846: a resolved call whose argument conversion may run a user Deref keeps
// a possible unchanged-subject continuation, so retained typestate answers
// change: full v785 / read v784.
// Merge of master full v791 / read v790 with #10846 full v785 / read v784:
// max of both sides + 1 gives full v792 / read v791.
// Merge of this batch's full v793 / read v792 with #10846 full v792 / read v791:
// max of both sides + 1 gives full v794 / read v793.
// #10770 slice 2a: Self method results and model-backed std types (String
// through Clone::clone) are typed exactly, so fewer conversions are flagged:
// full v786 / read v785.
// #10770 slice 2b: impl-parameter and model generic results (for example
// Result<String, E>::unwrap) are typed exactly.
// Merge of this batch's full v794 / read v793 with #10770 slice 2a full v786 / read v785:
// max of both sides + 1 gives full v795 / read v794.
// Merge receiver adjustment branch and current master: max + 1 gives v796.
// #10774+#10830: corrected Cargo manifest gaps change Rust call-target completion.
// #10774+#10830: above master full v791 / read v790: full v792 / read v791.
// Merge of master full v792 / read v791 with this branch's full v792 / read v791:
// max of both sides + 1 gives full v793 / read v792.
// Merge of master full v793 / read v792 with this branch: max of both sides + 1 gives full v794 / read v793.
// Merge of master's #10846/#10770 slice 2a full v795 / read v794 with this batch's #10774 full v794 / read v793:
// Merge of master full v795 / read v794 with #10770 slice 2b full v787 / read v786:
// Merge of master full v796 / read v795 (#10774) with #10770 slice 2b full v796 / read v795:
// Merge of master full v795 / read v794 with #10802 full v794 / read v793:
// Merge of master full v796 / read v795 (#10774) with #10802 full v796 / read v795:
// max of both sides + 1 gives full v797 / read v796.
// max of both sides + 1 gives full v796 / read v795.
// #10470: read completeness of JVM lookups changes for unchanged inputs; above master
// full v793 / read v792: full v794 / read v793.
// Promotion merge of this batch's full v794 / read v793 with master's
// #7314 M6a1: C# declared types change native answers.
// #10846/#10770 slice 2a/#10774 full v796 / read v795: max of both sides + 1
// gives full v797 / read v796.
// Promotion merge of this batch's full v797 / read v796 with master's
// #10470 full v797 / read v796: max of both sides + 1 gives full v798 / read v797.
// Merge of master full v797 / read v796 (#10470 batch) with #10802 full v797 / read v796:
// max of both sides + 1 gives full v798 / read v797.
// Batch merge of #10802 and #10770 slice 2c at master full v798 / read v797:
// max of both sides + 1 gives full v799 / read v798.
// #10770 slice 2c: workspace operator results through the operator trait's Output
// are typed exactly: full v797 / read v796.
// Merge of #10770 slice 2b full v797 / read v796 (master #10774 merged) with
// slice 2c full v797 / read v796: max of both sides + 1 gives full v798 / read v797.
// #10770: shared alias expansion changes selected conversion type answers.
// Coordinator-assigned full v799 / read v798 stays distinct from slices 2b and 2c.
// Promotion merge: master full v799 / read v798, above sibling barrier v800 / v799;
// shared alias expansion uses full v801 / read v800.
// Final PR merge: master v799/v798 and our parent v801/v800; use v803/v802,
// distinct from the sibling barrier reservation v804/v803.
// Merge of #10925 full v794 / read v793 with master full v795 / read v794: max of both sides + 1 gives full v796 / read v795.
// #10953: Rust crate summaries gain target-specific dependency tables and destination
// library names, so provider-dependent route answers change for unchanged inputs.
// Merge of master full v797 / read v796 and open c2 #10870 (v798/v797); taking c2's full v798 / read v797 with this branch: max of both sides + 1 gives full v799 / read v798.
// Merge of master full v798 / read v797 (#10946/#10961) and this branch's v799/v798; max is full v799 / read v798 with this branch: max of both sides + 1 gives full v800 / read v799.
// Merge of master full v799 / read v798 (#10955/#10957) and this branch's v800/v799; max is full v800 / read v799 with this branch: max of both sides + 1 gives full v801 / read v800.
// #9737 c2: Rust route answers for partial crates become unknown instead of
// negative, which changes provider-dependent summaries; above master full v783 /
// read v782: full v784 / read v783.
// Merge of master full v788 / read v787 with this branch's full v784 / read v783:
// Merge of #10774 full v792 / read v791 with this branch's full v789 / read v788:
// Merge of #10925 full v794 / read v793 with this branch: max of both sides + 1 gives full v795 / read v794.
// Merge of master full v795 / read v794 with this branch: max of both sides + 1 gives full v796 / read v795.
// Merge of master full v796 / read v795 with this branch: max of both sides + 1 gives full v797 / read v796.
// Merge of master full v797 / read v796 with this branch: max of both sides + 1 gives full v798 / read v797.
// Merge of master full v799 / read v798 (#10955/#10957) and open #10953 #10974 (v801/v800); above #10974's full v801 / read v800 with this branch: max of both sides + 1 gives full v802 / read v801.
// Merge of master full v801 / read v800 (#10953) and this branch's v802/v801; max is full v802 / read v801 with this branch: max of both sides + 1 gives full v803 / read v802.
// Final draft merge: parents v803/v802 and v801/v800; v805/v804 exceeds both,
// distinct from sibling barrier reservation v804/v803.
// Merge of master full v805 / read v804 and #10987's full v802 / read v801: max of both sides + 1 gives full v806 / read v805.
// Merge of master full v805 / read v804 (#11023) with this branch's full v803 / read v802: max of both sides + 1 gives full v806 / read v805.
// Merge of master full v806 / read v805 (#11023) and this branch's full v806 / read v805 (#10987): max of both sides + 1 gives full v807 / read v806.
// #9402: C# indexer declarations and the query-time member-identity discharge
// change provider results for unchanged bytes; above master v799/v798: v800/v799.
// Merge of master full v805 / read v804 with #9402 full v800 / read v799: max of both sides + 1 gives full v806 / read v805.
// Merge of master full v806 / read v805 with #9402 full v806 / read v805: max of both sides + 1 gives full v807 / read v806.
// Batch merge of two full v807 / read v806 sides (#10987/#11023 and #9402): max of both sides + 1 gives full v808 / read v807.
// #4307: std receiver adjustment summaries; parent selected 800/799 above
// master 591bb1c6dd full796/read795 and sibling pairs797/796,798/797,799/798.
// Pre-Ready merge b1bc97340c: parent-approved full800/read799 remains strictly
// above master full799/read798; preserve both domains and every master bump reason.
// #4307 final merge review: full802/read801 invalidates both parents
// (pre-merge800/799, master799/798) and exceeds the parallel alias pair801/800.
// #4307 last merge: parent assigned full804/read803 above prior802/801,
// master053bad7a40 full799/read798 and the parallel alias pair803/802.
// #4307 final submitted merge: owner selected full806/read805 above both parents
// (branch804/803 and master801/800) and the parallel alias pair805/804.
// #4307 alias merge: full807/read806 exceeds parents806/805 and805/804.
// #4307 mechanical merge: full808/read807 exceeds both parents807/806.
// #10989 M0: closed local containers bind complete Keyed collection-flow contracts
// to per-key cells, so value-flow answers change for unchanged inputs: full v802.
// Merge of master full v805 / read v804 with #10989 M0 full v802 / read v801: max of both sides + 1 gives full v806 / read v805.
// Merge of master full v807 / read v806 with #10989 M0 full v806 / read v805: max of both sides + 1 gives full v808 / read v807.
// Merge of #4307 full808/read807 and #10989 M0 full808/read807: max of both sides + 1 gives full809/read808.
// Promotion merge of master full808/read807 (#9402 and batch #11056) with this batch's full809/read808: max of both sides + 1 gives full810/read809.
// #10952: Rust trait inventories (unresolved impls, import candidates, macro
// occurrences) become recorded selected-live lookups, replacing the interim
// unattributed reads and correcting raw non-live answers: full v800 / read v799.
// Merge of master full v801 / read v800 (#11008 and earlier) and this branch's #10952 v800/v799: max of both sides + 1 gives full v802 / read v801.
// Merge of master full v806 / read v805 (#11023, #10870 and earlier) and this branch's #10952 v802/v801: max of both sides + 1 gives full v807 / read v806.
// Merge of master workspace-behavior at full v808 / read v807 (#11056 and earlier) with this branch's #10952 v807/v806: max of both sides + 1 gives workspace-behavior v809.
// #11036: a crate-local `log` item shadowing the log crate now refuses log macro
// admission, so retained Rust answers for those calls change: full v808 / read v807.
// Merge of master workspace-behavior at full v808 / read v807 (#11056 and earlier) with this branch's #11036 v808/v807: max of both sides + 1 gives full v809 / read v808.
// Batch merge of #10952 v809/v808 and #11036 v809/v808: max of both sides + 1 gives full v810 / read v809.
// #8296: C# model overloads select the exact-match member; above master v807/v806: full v808 / read v807.
// Merge of master full v808 / read v807 (#9402 batch) with #8296 full v808 / read v807: max of both sides + 1 gives full v809 / read v808.
// Batch merge of #10952/#11036 v810/v809 and #8296 v809/v808: max of both sides + 1 gives full v811 / read v810.
// #8298: a dotted C# type qualifier (`Serializer.Typeless.M()`) resolves its head through the using/alias ladder, so C# definitions and dispatch can name a nested external member; full v808 / read v807.
// Merge of master full v808 / read v807 (#9402 batch) with #8298 full v808 / read v807: max of both sides + 1 gives full v809 / read v808.
// Batch merge of #10952/#11036/#8296 v811/v810 and #8298 v809/v808: max of both sides + 1 gives full v812 / read v811.
// Promotion merge of master full v810 / read v809 with this batch's full v812 / read v811: max of both sides + 1 gives full v813 / read v812.
// #8299: C# receiver chains cross external members and typed-local residual
// conversions discharge at query time; master is full v807 / read v806.
// Merge of master full v813 / read v812 with #8299 full v808 / read v807: max of both sides + 1 gives full v814 / read v813.
// #9737 step d: Rust call-conversion proofs read per-question routes and abstain on
// partial crates where the whole route index answered; above master full v813 /
// read v812: full v814 / read v813.
// Batch merge of #11075 full v814 / read v813 with #11079 full v814 / read v813: max of both sides + 1 gives full v815 / read v814.
// #11069: declaration_facts cache hits replay their fill's receipt, so retained answers built on a warm hit gain read keys; above master full v813 / read v812: full v814 / read v813.
// Batch merge of #11075/#11079 full v815 / read v814 with #11085 full v814 / read v813: max of both sides + 1 gives full v816 / read v815.
// #11060: standalone analyzers certify their enumeration and unplaced modules keep topology partial, so retained Rust usage answers change; above master full v813 / read v812: full v814 / read v813.
// #8297: a C# reduced-form call to a model-declared static extension method now names that member, so C# definitions and dispatch change; above master v813/v812: full v814 / read v813.
// Merge of master full v814 / read v813 (#11060) with #8297 full v814 / read v813: max of both sides + 1 gives full v815 / read v814.
// Promotion merge of master full v814 / read v813 with this batch's full v816 / read v815: max of both sides + 1 gives full v817 / read v816.
// Promotion merge of master full v817 / read v816 with this batch's full v815 / read v814 (#11060, #8297): max of both sides + 1 gives full v818 / read v817.
// #8430 step 2: extern alias facts and alias-qualified routes change retained C#
// call-binding answers; above master full v818 / read v817: full v819 / read v818.
// Model alias target expansion and #11043 shared Named substitution/work alter
// canonical Rust proofs; coordinator assigned full v810 / read v809.
// Alias expansion merge: both parents full v810 / read v809; max + 1 gives full v811 / read v810.
// Final alias merge: parents full/read 811/810 and 813/812; max + 1 gives 814/813.
// Final model-alias submission merge: both parents full/read 814/813; max + 1 gives 815/814.
// Mechanical alias submission merge: parents 815/814 and 818/817; max + 1 gives full/read 819/818.
// Batch merge of master full v819 / read v818 (#8430 step 2) with this batch's
// full v819 / read v818 (#8297, model alias target expansion): max of both sides
// + 1 gives full v820 / read v819.
// #11111: certified-absent Rust modules preserve broad completeness; above master full v818 / read v817: full v819 / read v818.
// Batch merge of the landed full v820 / read v819 with #11111's full v819 / read
// v818: max of both sides + 1 gives full v821 / read v820.
// #10342: precise compilation import enumeration changes native answers; above master full v813 / read v812: full v815 / read v814.
// Merge master full v818 / read v817 with #10342 full v815 / read v814: set full v820 / read v819, above master.
// Merge of master full v819 / read v818 (#8430 step 2) with #10342 full v820 / read v819: max of both sides + 1 gives full v821 / read v820.
// #8430 step 3: alias-only C# qualified routes and read-B-certified absence.
// Merge #10342 full v821 / read v820 with #8430 step 3 full v825 / read v824: max of both sides + 1 gives full v826 / read v825.
// Promotion merge of master full v821 / read v820 with this batch's full v826 / read v825: max of both sides + 1 gives full v827 / read v826.
// #11089: unready Rust inventories report candidate-scoped incompleteness; above master full v818 / read v817: full v819 / read v818.
// Merge of master full v819 / read v818 (#8430 step 2) with #11089 full v819 / read v818: max of both sides + 1 gives full v820 / read v819.
// Merge of master full v821 / read v820 (#11111 batch) with #11089 full v820 / read v819: max of both sides + 1 gives workspace-behavior v822.
// Batch promotion merge of master full v827 / read v826 with this batch's full v822 / read v821:
// max of both sides + 1 gives full v828 / read v827.
// #4967 C: the Rust ? residual proof binds generic alias parameters, so inert and residual
// dispatch answers change for unchanged bytes; above master v828/v827: full v829 / read v828.
// #7314 M6a1: declared types and global predefined aliases; full v821 / read v820, above master full v818 / read v817.
// Merge of master full v819 / read v818 (#8430 step 2) with #7314 M6a1 full v821 / read v820: max of both sides + 1 gives full v822 / read v821.
// Merge of master full v821 / read v820 (#11111 batch) with #7314 M6a1 full v822 / read v821: max of both sides + 1 gives full v823 / read v822.
// Merge of master full v827 / read v826 with #7314 M6a1 full v823 / read v822: max of both sides + 1 gives full v828 / read v827.
// Merge of master full v828 / read v827 with #7314 M6a1 full v828 / read v827: max of both sides + 1 gives full v829 / read v828.
// Merge of #4967 C full v829 / read v828 with #7314 M6a1 full v829 / read v828:
// max of both sides + 1 gives full v830 / read v829.
// #4967 C slice 3: an awaited direct `async fn` call types the ? residual, and a sync call
// on an async callee no longer does; above master v830/v829: full v831 / read v830.
// #7314 M10a0: per-framework symbols change retained branch decisions.
// #7314 M10a0 symbols final merge: master full v833, assigned full v836 / read v835.
// #10497: JVM dispatch families follow external intermediate supertypes (index and pack) and open on an unresolved one; above master full v828 / read v827 and #11051's queued v829 / v828: full v830 / read v829.
// #10497 merge: max(master full v833 / read v832, lane full v830 / read v829) + 1 = full v834 / read v833.
// Batch merge of master full v837 / read v836 with #10497 full v836 / read v835:
// max of both sides + 1 gives full v838 / read v837.
pub const WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN: &[u8] =
    // #7314 M10a0 part 2: named-open C# symbols change provider answers; full v819 above master full v813 / read v812.
    // #7314 M10a0 part 2: named-open C# symbols change provider answers; above master full v819 / read v818: full v820 / read v819.
    // #11111 merge: parents full v820 / read v819 and full v819 / read v818; max + 1 is v822/v821.
    // #7314 M10a0 part 2 final merge: master full v821/read v820; assigned full v824/read v823.
    // #10342 / #8430 step 3 merge: current master full v827 / read v826; assigned full v829 / read v828.
    // #11156/#11158 latest master full v828 / read v827; M6a1 reserves v829 / read v828; this lane assigned v832 / read v831.
    // Promotion merge of master full v830 / read v829 with this batch's full v832 / read v831:
    // max of both sides + 1 gives full v833 / read v832.
    // Merge of master full v833 / read v832 with #4967 C slice 3 full v831 / read v830:
    // max of both sides + 1 gives full v834 / read v833.
    // Promotion merge of our full v836 / read v835 with master full v834 / read v833:
    // max of both sides + 1 gives full v837 / read v836.
    // #10497 final master merge: max(master v834, lane v834) + 1 gives full v835.
    // #10497 Ready merge: max(master full v834, lane full v835) + 1 gives full v836.
    // Batch merge of master full v837 / read v836 with #10497 full v836 / read v835:
    // #11173: removing the Rust reverse external-root discharge can turn a complete usages or call-relation answer incomplete; above master full v833 / read v832: full v834 / read v833.
    // Merge of master full v837 / read v836 with #11173 full v834 / read v833:
    // max of both sides + 1 gives full v838 / read v837.
    // Promotion merge of master full v838 / read v837 with this batch's full v838 / read v837:
    // max of both sides + 1 gives full v839 / read v838.
    b"bifrost-icfg-provider/workspace-behavior/v839";

/// The domain of the same behavior without the workspace's content identity.
///
/// Its own domain rather than a shorter message under the one above, so that
/// no read half can ever equal a full identity by accident.
// #7202: rotate read-side reuse with the classified result identity contract.
// #7518: rotate read-side reuse with the Go undecided-receiver incoming answers.
// #7578: rotate read-side reuse with branch-conditioned sanitizer kills.
// #7618: Rotate the ICFG read identity for Java native receiver binding.
// #7516: rotate read-side reuse with the Go constructor-shadow answers.
#[doc(hidden)]
// #7578: rotate read-side reuse with requirement-writer reachability.
// #7619: invalidate read-side reuse for inherited external call binding.
// #7620: read identities also invalidate Java wildcard call proofs.
// #6234: invalidate read reuse for implicit receiver value bindings.
// #7509 M3a: rotate read-side reuse with the Go declaration value types.
// #3494: read identities also invalidate Ruby closed member selections.
// #7789: read identities also invalidate JVM import destinations.
// #7849: read identities also invalidate Java guard proofs over external-owner carriers.
// #7509 M3a part 2: rotate read-side reuse with the native Go binding proofs.
// Quicksilver round 13: rotate read-side reuse with Go method-expression non-return discovery.
// #7918: rotate read-side reuse with Go field selector addressability.
// #7915: rotate read-side reuse with the flow carrier comparison.
// #5658 switches production Python query answers to the native engine.
// #7779: invalidate read-side reuse for exact owner inventory proofs.
// #7509 PR B: rotate read-side reuse with native Go model-owner selection.
// #7868: forward and reverse reads retain settled-root evidence.
// #7876: invalidate read-side reuse for incomplete cache builds.
// #7509: rotate read-side reuse with relative Go source imports.
// Quicksilver round 13 value_flow: rotate read-side reuse with caller-origin evidence.
// #7351: rotate read-side reuse with native Go method-set failure-handler proofs.
// #7886: read reuse follows native nested budget and cancellation propagation.
// #8036: invalidate reads for native Go external receiver call identities.
// #7968: rotate read-side reuse with shared Go satisfaction membership.
// #7509 G1b-1: rotate read-side reuse with native owners behind incomplete Go imports.
// #7362: forward query obligations change query-time bindings and diagnostics.
// #6664: invalidate reads that took a failed descendant read as a complete empty set.
// #8153: rotate read-side reuse with overload-ambiguous incoming call targets.
// #8000: invalidate read reuse when selected JVM on-demand candidates bind.
// #7509 G1b-2: rotate read-side reuse with native Go modeled callable results.
// #6945: invalidate read-side reuse for curated Python star child bindings.
// #7240: invalidate read-side reuse for imported constructor receiver proofs.
// #2445: rotate read-side reuse with hierarchy_unenumerated external member-family boundaries.
// #8264: rotate read-side reuse with predeclared Go modeled result types.
// #7509 G1b-3 B: rotate read-side reuse with the selected-callable pointer-field proof.
// #8147 M4a: rotate read-side reuse with C# preprocessor decisions.
// #8290: invalidate read reuse taken from warm reads that lost closure discharges.
// #8167 S2/S5: invalidate read reuse for widening-driven applicability answers.
// #8222: invalidate read reuse for Scala implicit-root order and alias answers.
// #8403: rotate read-side reuse with the Rust reverse applicability gaps.
// #8193: classify unenumerated dispatch separately from budget exhaustion.
// #8385: same-priority definition candidates in different files tie-break by source path, not absolute start byte.
// #7509 G1b-3 A: rotate read-side reuse with native exact-binding result identity.
// #8184/#8126: rotate read-side reuse with retained fills that record only their own reasons.
// #8191: rotate read-side reuse with the shared retained-fill domain.
// #8415: invalidate read reuse for enclosing JVM signature scopes.
// #8388: rotate read-side reuse with caller-inventory coverage.
// #8457: rotate read-side reuse with Rust trait-impl dispatch openness.
// #8453: rotate read-side reuse with Go method dispatch openness.
// #8546: rotate read-side reuse built while model overrides ignored their analyzer.
// #8402: rotate read-side reuse with Go artifacts served from parse-time rows.
// #8418/#8333: replay corrected external nominal closure selection (rung v287).
// #8579: rotate read-side reuse with Java, Kotlin and C# artifacts served from parse-time rows.
// Batch 49878eab: combine #8579 with master (v302 vs v303); the two halves move together.
// #7750: rotate read-side reuse with Java guarded-switch lowering.
// Batch 082b6a23: combine #8589 with the batch (v304 vs v305); the two halves move together.
// #8283: rotate read reuse with structural Go result proofs.
// Batch 082b6a23: combine #8594 with the batch (v306 vs v313); the two halves move together.
// #7509 G1b-3 F: rotate read-side reuse with native nested-call result counts.
// Batch d1bb2a8e: combine #8517 with the batch (v314 vs v311); the two halves move together.
// #8602: rotate read reuse for observer-free exceptional exits.
// Batch 1648c5ee: combine #8653 with the batch (v315 vs v317); the two halves move together.
// #8586: rotate read-side reuse built when on-demand completion followed the request budget.
// Batch 1648c5ee: combine #8692 with the batch (v318 vs v321); the two halves move together.
// #8665: invalidate reads made without the Scala import bridge boundaries.
// Batch 8efa980f: combine #8712 with the batch (v322 vs v329); the two halves move together.
// #7027 S2b-0: invalidate read reuse for implicit-root hierarchy and member answers (rung v307).
// #7027 S2b-0 r3: reserve v331 above master v314 with the behavior-domain rung.
// #7027 S2b-0 merge2: coordinator reassigned v351 above master v330 and queued #8727 v332.
// #8516: package member provider reads change query-time answers; assigned above master v316/v315.
// Batch cb42f2c0: combine #8531 with the batch (v330 vs v337); the two halves move together.
// #8705: rotate read-side reuse with open Scala implicit-root gaps.
// Merge #8705 with master after #8712 (v331 vs v330); the two halves move together.
// Batch cb42f2c0: combine #8727 with the batch (v338 vs v332); the two halves move together.
// #8667: rotate read-side reuse built before deterministic Go nested-call arity gaps.
// #7509 G1b-3 G: rotate read-side reuse built when untyped nested selector receivers stayed open.
// Batch c1b44b74: combine #8667 (v363) with #7509 G1b-3 G (v365); the two halves move together.
// Batch 676be8c9: combine #7027 S2b-0 (v351) with master (v366); the two halves move together.
// #7960: rotate read-side reuse built before JavaScript call throws reached catch binders.
// Merge #8741 with master v368/v367; the two halves move together.
// Merge #8741 with master v376/v375 at the coordinator-assigned v384/v383; the two halves move together.
// #7619: rotate read-side reuse with projected JDK call-result receiver binding.
// #8792: rotate read-side reuse for the Kotlin lambda binder facts.
// Batch 30414977: combine #8820 (v402) with master (v376); the two halves move together.
// #8836: rotate read-side reuse built while JavaScript call throws reached catch binders.
// Batch 30414977: combine #8844 (v394) with #8820 (v403); the two halves move together.
// #7509 3a: rotate read-side reuse built when the legacy Go binding walk chose call roles.
// #8872: rotate read-side reuse that discarded proven package-module receivers.
// #7509 5b step 1: rotate read-side reuse built from the legacy Go typed selector target.
// Batch 66a984a8: combine #8881 (v427) with #8888 (v435); the two halves move together.
// Batch 66a984a8 promotion: combine master #8874 (v425) with this batch (v436); the two halves move together.
// #8388: invalidate read reuse that treated shadowed Go builtins as complete.
// Batch c536ab7b: combine master (v437) with #8895 (v437); the two halves move together.
// Merge: combine #8888 (v435) with master #8874 (v425); the two halves move together.
// #7509 5b step 2: rotate read-side reuse built from the legacy Go allocation selector inference.
// Batch 7dd04e18: combine master (v438) with #8901 (v441); the two halves move together.
// #8823: rotate read-side reuse built while the generated JDK pack was rejected.
// Batch 7dd04e18 update: combine master #8823 (v461) with this batch (v442); the two halves move together.
// #8870: composed entry-point origins change read-side answers.
// Batch 7880504b promotion: combine master (v462) with #8903 (v445); the two halves move together.
// #7509: rotate reads built with a bound receiver for a function-valued field.
// Batch 9dd7ee48: combine master (v463) with #8916 (v475); the two halves move together.
// #8866: rotate read-side reuse built while unwrapped Rust receivers stayed unresolved.
// Batch 7e70b7bc: combine master (v463) with #8866 (v473) and #8884 (v469); the two halves move together.
// #8884: rotate read-side reuse built while Rust external proofs read live pooled imports.
// Batch 7e70b7bc promotion: combine master (v476) with this batch (v474); the two halves move together.
// #8822: rotate read-side reuse for closed C# inventory derivations.
// Batch d50922f0: combine master (v476) with #8924 (v481); the two halves move together.
// #7509 5b step 3: rotate read-side reuse built from legacy Go nested-call count inference.
// Batch d50922f0: combine this batch (v482) with #8928 (v485); the two halves move together.
// Batch d50922f0 promotion: combine master (v477) with this batch (v486); the two halves move together.
// #8803: rotate read-side reuse for C# enclosing namespace scope selection.
// Coordinator reassigned the #7619 pair to v498/v497 above master v489/v488.
// #7509 G2: rotate read-side reuse built while structural signature slots were never proven.
// #7869: rotate read-side reuse with per-reference JVM provider obligations (rung v479, coordinator).
// Batch 5aea0d33: combine master (v487) with #8679 (v479); the two halves move together.
// #8870: composed store ends change the workspace taint read behavior identity;
// coordinator assigned v496/v495 above master v489/v488 and every reserved pair.
// Batch 8da812cd promotion: combine master (v489) with this batch (v495); the two halves move together.
// #8870: composed flow policies read the complete endpoint inventory.
// Set to v506/v505, the coordinator's assignment above master v497/v496 and the open pairs through v504.
// Batch 5b711078: combine master and #7728 (v496, v497); the two halves move together.
// #8487: rotate read-side reuse with frame-owned Java package outcomes (rung v507, coordinator).
// #8992: rotate read-side reuse with declared-owner glob admission (rung v515, coordinator).
// Batch 5b711078: combine master and #8915 (v498, v515); the two halves move together.
// Batch 5b711078: combine master and #8973 (v503, v516); the two halves move together.
// Batch 6a13abe4 promotion: combine master (v517) with #8995 (v505); the two halves move together.
// #7804: rotate read-side reuse with rooted Java expression prefixes and targetless terminal proof; coordinator assigned v521 above master v517.
// Batch 565a8ef8: combine master (v518) with #7804 (v521); the two halves move together.
// Batch 7dcb059c: combine master (v522) with #9034 (v531); the two halves move together.
// #9063: rotate read-side reuse with certified Go method-set collisions; coordinator assigned v539 above master v532.
// Batch 378fac65: combine master (v532) with #9063 (v539); the two halves move together.
// #9053: rotate read-side reuse built while Go model-interface calls had no receiver preparation.
// #8834: rotate read-side reuse built before selected JVM root presence reads were recorded;
// coordinator assigned v514/v513 above master v497/v496 and every reserved pair.
// Coordinator re-assigned the #8834 pair to v524/v523 above master v518/v517.
// Coordinator re-assigned the #8834 pair to v542/v541 above master v533/v532 and the reserved pairs through v540.
// Coordinator re-assigned the #8834 pair to v550/v549 above master v548/v547 and the reserved pairs.
// Batch 02d43023 (#8834): combine v547 with v549; the two halves move together.
// #8811: the same replay change rotates read-side answer reuse.
// Coordinator reassigned the #8811 pair to v494/v493 above master v489/v488.
// Coordinator reassigned the #8811 pair to v510/v509 above master v497/v496.
// Coordinator re-assigned the #8811 pair to v526/v525 above master v518/v517.
// Coordinator re-assigned the #8811 pair to v544/v543 above master v533/v532 and the reserved pairs through v540.
// Coordinator re-assigned the #8946 pair to v552/v551 above master v548/v547 and the reserved pairs.
// Batch 02d43023 (#8946): combine v550 with v551; the two halves move together.
// #9101: rotate read-side reuse built while model-interface member selection was incomplete; coordinator assigned v557 above master v547.
// Batch e4fc49ee (#9101): combine master v552 with #9101 v557 as max + 1; the two halves move together.
// #9050: rotate read-side reuse built while Rust type lookup ignored model-declared external types; coordinator assigned v549 above master v540.
// Merge for #9050: combine master (v547) with #9050 (v549); the two halves move together.
// Merge for #9050: combine master (v552) with #9050 (v550); the two halves move together.
// Merge for #9050: combine master (v558) with #9050 (v553); the two halves move together.
// #8929 (#8896): read-side ICFG plans include copied argument members;
// v561 is the paired coordinator-assigned read behavior domain.
// #9196: read-side reuse follows the same invocation/root/capture and Rust
// local-closure dispatch change; v565 is paired with full behavior v566.
// #9060: read-side ICFG plans rotate with typed-round call-result forwarding;
// v567 is the paired coordinator-assigned read behavior domain.
// #9195: read-side reuse follows native Scala's selected source alias parents;
// v571 is paired with full behavior v572.
// #9220: read-side plans follow the same renamed object-member import answers;
// v577 is paired with full behavior v578.
// #6291: read-side reuse follows the native Java import-boundary correction
// through CallDispatchLookup.boundary into workspace ICFG call transfers;
// v581 pairs with full behavior v582.
// #6792: read-side provider reuse follows the same bare Scala term answers;
// v589 is paired with full behavior v590.
// #9194: local_type_binding enters the same Unproven boundary proof;
// v587 is the paired coordinator-assigned read behavior domain.
// Merge of #9194 with #6792 (v587 and v589): v590 pairs with full v591.
// #7654: read-side reuse follows the selected Object member dispatch proof;
// v597 pairs with full behavior v598.
// #7509: read-side reuse follows the same sole-spec Go alias bridge path;
// v603 pairs with full behavior v604.
// #9195: v607 pairs with full v608 for selected reference package reads.
// #9323: read-side reuse follows the same default-import and static-call answers;
// v615 pairs with full behavior v616.
// Batch merge of #9195 (v607) and #9323 (v615): max + 1 = v616, pairs with full v617.
// #7726: read-side reuse follows the same Kotlin call proof; v617 pairs with v618,
// and merged with master's v616: max + 1 = v618, pairs with full v619.
// #8307: read-side reuse follows the same C# member-in-element-access answer;
// v621 pairs with full behavior v622.
// Batch merge of #9414 (v621) and the batch (v618): max + 1 = v622.
// #8826: read-side reuse follows the C# global-alias target correction;
// v619 pairs with full behavior v620.
// Batch merge of #8826 (v619) and master (v622): max + 1 = v623, pairs with full v624.
// #9277: read-side reuse follows the selected Go context correction.
// Coordinator assigned read v617 paired with full behavior v618.
// Batch merge of #9344 (v617) and the batch (v623): max + 1 = v624.
// #7960: read-side reuse follows the same catch bindings and definition
// alternatives; v619 pairs with full behavior v620.
// Merge of #7960 (v619) with master (v616): max + 1 = v620, pairs with full v621.
// Batch merge of #9413 (v620) and the batch (v624): max + 1 = v625.
// #9336: read-side reuse follows the same Ruby singleton-call proof; v621
// pairs with full behavior v622.
// Batch merge of #9425 (v621) and the batch (v625): max + 1 = v626.
// #9336 follow-up: read-side reuse follows the same workspace singleton-rewrite
// scan; v623 pairs with full behavior v624.
// Batch merge of #9429 (v623) and the batch (v626): max + 1 = v627.
// #9378: read-side reuse follows the same indexed modeled results; v635 pairs
// with full behavior v636 (v623 retired after the #9429 collision).
// Batch merge of #9404 (v635) and the batch (v627): max + 1 = v636.
// #9323: read-side reuse follows the same constructor callees; v620 pairs with v621.
// Batch merge of #9323 (v620) and master (v623): max + 1 = v624, pairs with full v625.
// Batch merge of #9422 (v624) and the batch (v636): max + 1 = v637.
// #9378 S2: read-side reuse follows the same Go handoff answers; v631 pairs
// with full behavior v632.
// Batch merge of #9426 (v631) and the batch (v637): max + 1 = v638.
// #7509: v639 pairs with full v640 for directional Go channel reads.
// #9322: read-side reuse follows the same yielded block-parameter receivers;
// v633 pairs with full behavior v634.
// Merge of #9322 (v633) with master (v638): max + 1 = v639, pairs with full v640.
// Merge of #9322 (v639) with master (v639): max + 1 = v640, pairs with full v641.
// #9324: v641 pairs with full v642.
// Merge of #9324 (v641) with master (v640): max + 1 = v642, pairs with full v643.
// #9438: decorator argument edges reach semantic-model overlay rules and captures;
// read-side reuse must follow the same provider behavior. v645 pairs with full v646.
// Merge of #9438 (v645) with master (v642): max + 1 = v646, pairs with full v647.
// #9060: read-side plans follow the same semi-naive typed-round answers;
// v601 pairs with full behavior v602.
// v621 pairs with full behavior v622 for the reassigned #9060 pair; after the
// #9414 collision, v627 pairs with full behavior v628.
// #9300 (#9060): read-side reuse follows the same semi-naive answers; v647
// pairs with full v648 (v627 retired).
// Merge of #9300 with master read v642 (#9324): v647 stays above, pairing with v648.
// Merge of #9300 with master read v646 (#9438): v647 stays above, pairing with v648.
// #9532: v652 pairs with full v653.
// #5658: rotate read-side reuse built from the legacy Python resolver; coordinator assigned v657/v656.
// #9447: read-side call transfers follow formal-role proofs and stable local Go
// function-literal target/capture answers; v648 pairs with full behavior v649.
// #9447: the assigned pair remains above merged master v648/v647.
// #9532: v652 pairs with full v653.
// #9183: read v660 pairs with full v661 (coordinator-assigned 2026-11-04).
// #5658: rotate read-side reuse built from the legacy Python resolver; coordinator assigned v657/v656.
// Certified source-call application-result obligations share this read identity.
// #9447: merge with master v653/v652 takes max of each side plus one;
// the coordinator-assigned full v654/read v653 replaces v649/v648.
// #9447: merge with master v657/v656 takes max of each parent plus one,
// producing full v658/read v657 before the separately assigned identity carry.
// #9447: the coordinator renews the unpublished pair to full v660/read v659
// above master v657/v656 and distinct from the held v658 and v659 full domains.
// #9522: receiver Incomplete candidates change open dispatch and coverage answers;
// v658 pairs with full v659.
// #9557: v661 paired with full v662; merged with #9522, v662 pairs with full v663.
// #8675 S2: v664 pairs with full v665.
// #9183: read v667 pairs with full v668 (coordinator renewal, 2026-11-04).
// #9575: Python mutation queries rescan instead of reusing stopped or unreceipted outcomes;
// coordinator assigned v662 paired with full v663.
// #9575 master merge: both read domains were v662; max + 1 = v663, paired with full v664.
// #9575: renewed read v665 pairs with full v666; the policy component is unchanged.
// #9575 coordinator renewal: read v670 pairs with full v671; prior pairs retired.
// #9575/#9546 conflict resolution: intermediate full v672 = max(671, 669) + 1; read v671.
// #9546 M1a: v668 pairs with full v669.
// #9563: v669 pairs with full v670; read-side reuse follows the changed answer and attribution meaning.
// #9575: final read v674 pairs with full v675 after current-master composition.
// #9563/#9575 merge: read v675 = max(v669, v674) + 1, paired with full v676.
// #9447: importing #9575 takes max(v659, v674) + 1 on read identities;
// read v675 pairs with the assigned full v676.
// #9183: read v678 pairs with full v679 after the #9547 dependency import.
// #9563: v669 pairs with full v670; read-side reuse follows the changed answer and attribution meaning.
// #9447 queue correction: coordinator-assigned read v679 pairs with full v680;
// the prior unpublished read v675 is retired for this corrected composition.
// #9447 landed-prerequisite merge: coordinator-assigned read v682 pairs with full v683;
// the unpublished read v679 is retired for this composition.
// #9183: read v683 pairs with full v684 for corrected #9547 composition.
// #9002: v644 pairs with full v645 for protected lexical head reasons.
// Merge of #9002 (v644) with master (v646): v650 pairs with full v651, as assigned.
// Merge of #9002 with #9563 (v669): v677 pairs with full v678, as assigned.
// Merge of #9002 (v677) with master v675: v684 pairs with full v685, as assigned.
// Batch merge of #9002 (v684) with master v682 (#9447): read v685 pairs with full v686.
// #8837: v673 pairs with full v674.
// #8837 coordinator renewal: read v681 pairs with full v682.
// #8837 coordinator renewal: read v687 pairs with full v688.
// #9183 renewal above master v685: this composition uses v686.
// Batch merge of #9183 (v686) with master v687 (#8837): read v688 pairs with full v689.
// #9779: read v688 pairs with full v689 for the C++ lexical and formal recovery repair.
// Batch merge of #9779 (v688) with master v687 (#8837): read v689 pairs with full v690.
// Merge of master read v689 (#9779) into the #9183 batch (read v688): read v690 pairs with full v691.
// #9835: read identity pairs with full v697 after ordinal substitution.
// #9784: read v692 pairs with full v693 for recorded stored semantic IR publication reads.
// #8500: v690 pairs with full v691, as assigned.
// #8500 coordinator renewal: read v693 pairs with full v694.
// #9784: coordinator renewal: read v697 pairs with full v698 above master v695 (#9550).
// #9550: coordinator allocation read v688 above #9579 read v686 and master v685.
// #9550: current-master composition uses coordinator-assigned read v691.
// #9550: read v695 pairs with full v696 for honest call-closure summaries.
// #9651: read v698 pairs with full v699 (v676 retired).
// #9835: the merge with #8500 conflicted on this pair, so the coordinator renewed it to full
// v697 / read v696 (v695/v694 retired; v696/v695 is held by #9550).
// #9835: the merge of master 044662f15e (#9550 at full v696 / read v695) conflicted again, so the
// coordinator renewed this change to full v700 / read v699; v697/v696 is retired (v699/v698 is #9702).
// Batch merge of #9856: max of both sides + 1 gives full v701 / read v700.
// Batch merge of #9910: max of both sides + 1 gives full v702 / read v701.
// #9783: read v701 pairs with full v702 for explicit-import owner admission.
// #9783: renewed with the full half above master 760c5166d7: read v703 pairs with full v704.
// #9840: read v702 pairs with full v703 for the dependency-evidence digest.
// #9840: the coordinator renewal pairs read v704 with full v705 after the master ff83fe24db conflict.
// Batch merge of #9840: read v705 pairs with full v706.
// #9852: read v702 pairs with full v703 for certified external Go signature leaves.
// #9852: coordinator renewal: read v705 pairs with full v706.
// Batch merge of #9852: read v706 pairs with full v707.
// #9900: read v696 pairs with full v697 for parameter-typed member-family edges.
// Merge of master read v701 (#9910) into #9900 (read v696): read v702 pairs with full v703.
// Batch merge of #9939: read v707 pairs with full v708.
// #9677: read v702 pairs with full v703 for explicit-import Kotlin receivers.
// Batch merge of #10016: read v708 pairs with full v709.
// #9324: read v702 pairs with full v703 for inapplicable external overload access gaps.
// Merge of #9324 (read v702) with master v707/v706: read v707 pairs with full v708.
// Batch merge of #10024: read v709 pairs with full v710.
// #7708: read v710 pairs with full v711 for declared type-argument transport.
// #9479: Scala parameterless selections become dispatch sites; full v703 / read v702.
// Merge of #9479 (read v702) with master v710/v709: read v710 pairs with full v711.
// #9423: read v707 pairs with full v708 for JVM external supertype targets.
// Merge of master read v709 (#10024) into #9423: read v710 pairs with full v711.
// Batch merge of #9479 (read v710) with #9423 (read v710): read v711 pairs with full v712.
// #10021: read v709 pairs with full v710 for creation types from their qualifier.
// #10021: renewed above #10024: read v711 pairs with full v712.
// Batch merge of integrated read v711 with #10021 read v711: max of both sides + 1 gives read v712.
// Merge of master read v712 with #7708 read v710: read v713 pairs with full v714.
// #9766: read v714 pairs with full v715 for separated return members.
// #9324: read v714 pairs with full v715 for Scala reference conversions.
// Merge of master read v714 with #9324 read v714: max of both sides + 1 gives read v715
// paired with full v716.
// #9995: read v716 pairs with full v717 for Scala external companion apply and String applicability.
// Merge of #9995 (read v716) with master read v715: max of both sides + 1 gives read v717 paired with full v718.
// #5658 M8 step 1a: read v712 pairs with full v713 for native Python definition dispatch.
// #5658 M8 step 1a: renewed with the full half: read v722 pairs with full v723.
// Merge of master read v713 (#7708) into #5658 M8 step 1a: read v722 pairs with full v723.
// #5658 M8 step 1a: renewed with the full half: read v723 pairs with full v724.
// #9423: read v718 pairs with full v719 for Kotlin property reads of Java getters.
// Merge of master read v723 with #9423 read v718: max of both sides + 1 gives read v724 paired with full v725.
// #5658 M8 P1: read v732 pairs with full v733 for discharged classmethod receiver gaps.
// #10385: read v725 pairs with full v726 for caller-decided external JVM member access.
// Merge of master read v732 with #10385 read v725: max of both sides + 1 gives read v733 paired with full v734.
// #5658 M8 P2: read v733 pairs with full v734 for annotation application heads.
// #5658 M8 P2: renewed with the full half: read v734 pairs with full v735.
// #8675 S3 (#9324): read v725 pairs with full v726 for Scala term-path heads and qualified members.
// Merge of master read v734 with #8675 S3 read v725: max of both sides + 1 gives read v735 paired with full v736.
// #10388: read v725 pairs with full v726 for declaration-scoped JVM producer warnings.
// Merge of master read v735 with #10388 read v735: max of both sides + 1 gives read v736 paired with full v737.
// #7643: read v719 paired with full v720, renewed to read v725 with full v726, then to read v738
// with full v739, then to read v741 with full v742, for different-owner supertype argument projection.
// Merge of master full v737 / read v736 with #7643 full v742 / read v741:
// max of both sides + 1 gives full v743 / read v742.
// #10445: Scala parameter bindings activate after their own clause, so resolution
// and dispatch answers change for unchanged bytes; rotate both halves together.
// #5658 M8 P3: read v747 pairs with full v748 for callees that carry only the callable result.
// #5658 M8 P3: renewed with the full half after the #10445 merge: read v750 pairs with full v751.
// #9224: read v713 pairs with full v714 for the target-keyed Go match.
// #9224: coordinator renewal: read v724 pairs with full v725.
// #9224: coordinator fresh pair: read v730 pairs with full v731.
// #9224: coordinator fresh pair: read v736 pairs with full v737.
// #9224: coordinator re-allocation: read v743 pairs with full v744.
// #9224: coordinator re-allocation: read v748 pairs with full v749.
// #9224: coordinator fresh pair: read v752 pairs with full v753.
// #10106: read v716 pairs with full v717 for unprovided written Go types.
// #10106: renewed read v731 pairs with full v732.
// #10106: coordinator fresh pair: read v737 pairs with full v738.
// #10106: coordinator re-allocation: read v744 pairs with full v745.
// #10106: coordinator re-allocation: read v749 pairs with full v750.
// #10106: coordinator fresh pair: read v753 pairs with full v754.
// #5658 M8 P5: coordinator fresh pair: read v757 pairs with full v758.
// #5658 M8 P5: coordinator renewal after the master merge: read v759 pairs with full v760.
// #10020: read v754 pairs with full v755 for member selections that no longer bind a local.
// #10020: merged above master: read v760 pairs with full v761.
// #5658 M8 P4: coordinator fresh pair: read v759 pairs with full v760.
// #5658 M8 P4: coordinator re-allocation: read v760 pairs with full v761.
// #5658 M8 P4: coordinator fresh pair after the master merge: read v761 pairs with full v762.
// #7860: read v764 pairs with full v765 for receiver type-argument substitution.
// Merge of master read v761 with #7860 read v764: max of both sides + 1 gives read v765
// paired with full v766.
// #10466: read v756 pairs with full v757 for the rejected-return-member coverage type.
// #10466: renewed: read v762 pairs with full v763.
// #10466: master reached v766/v765 (#10532), so the identity reviewer renewed: read v767
// pairs with full v768.
// #10526: read v766 pairs with full v767 for the Go literal-owner reason.
// Merge of master read v767 with #10526 read v766: max of both sides + 1 gives
// read v768 paired with full v769.
// #10000: read v766 pairs with full v767 for external Java constructor overload families.
// Merge of master read v767 with #10000 read v766: max of both sides + 1 gives read v768
// paired with full v769.
// This integration merge combines master read v768 with #10000 read v768: max of both
// sides + 1 gives read v769 paired with full v770.
// #7860 slice 2 A: read v770 pairs with full v771 for the field-named method identity.
// #9869: read v771 pairs with full v772 for Go constrained source-inventory callers.
// #10432: native Java call-row conversions are proven against the selection's type-argument
// bindings, so retained conversion and binding answers change; above master v772/v771:
// full v773 / read v772.
// #5658 M8 Python native type switch: read v772 pairs with full v773.
// This integration merge combines master read v772 with #10653 read v772: max of both
// sides + 1 gives read v773 paired with full v774.
// #9332: read v774 pairs with full v775 for omitted saved-default formals.
// #10563: read v775 pairs with full v776 for reads through stored references.
// #10582: signature-class reads govern Go interface conversions (read v774 with full v775).
// #10689: rank semantic model evidence within each language family.
// This integration merge combines read v776 / full v777 with the batch's #10563
// read v775 / full v776: max of both sides + 1 gives read v777 paired with full v778.
// This integration merge combines read v775 / full v776 with #10689 read v774 /
// full v775: max of both sides + 1 gives read v776 paired with full v777.
// #10052: read v728 pairs with full v729 for Fenced pack family dispositions in C# external dispatch.
// Merge of master read v733 with #10052 M2 read v728: fresh read v735 paired with full v736.
// Merge of master read v753 with #10052 M2 read v735: fresh read v758 paired with full v759.
// #10052 M2: read v770 pairs with full v771, one above master and #10589.
// #10052 M2 final merge: read v774 pairs with full v775, one above master.
// #10052 M2 final merge (2026-11-08): read v777 pairs with full v778, one above master.
// #10052 M2 final merge (2026-11-08 11:25Z): read v778 pairs with full v779, one above master.
// #8804: read v775 pairs with full v776 for relayed exceptional returns.
// Merge of master read v777 with #8804 read v775: max of both sides + 1 gives read v778
// paired with full v779.
// Promotion merge of master #8804 read v778 / full v779 with the batch's #10052
// read v778 / full v779: max of both sides + 1 gives read v779 paired with full v780.
// #7314 AD3d: read v779 paired with full v780 (membership is not a read input either).
// Merge of master read v779 / full v780 with #7314 AD3d read v779 / full v780:
// max of both sides + 1 gives read v780 paired with full v781.
// #10683: read v779 pairs with full v780 for identity prefix stores.
// Promotion merge of master read v779 / full v780 with the batch's #10683
// read v779 / full v780: max of both sides + 1 gives read v780 paired with full v781.
// #10812: read v781 pairs with full v782 for type-selected model overloads.
// Promotion merge with master bb6a872a read v780 / full v781 and this branch's
// read v780 / full v781: max of both sides + 1 gives read v781 paired with full v782.
// Promotion merge with master read v781 / full v782 and this batch's
// read v781 / full v782: max of both sides + 1 gives read v782 paired with full v783.
// #10357: selected file-program evidence opens otherwise empty C# membership; above master full v783 / read v782: read v783 pairs with full v784.
// #10356: derived Razor SDK projects inherit default Compile membership; above master full v784 / read v783 (#10357): read v784 pairs with full v785.
// Merge of master full v784 / read v783 (#10357) with this branch's full v785 / read v784: max of both sides + 1, past the open #7314 pairs, gives read v787 pairs with full v788.
// #10687 B: read v779 pairs with full v780 for conversion-weakened transfers.
// Merge of master read v779 with #10687 B read v779: max of both sides + 1 gives read
// v780 paired with full v781.
// Merge of master read v781 with #10687 B read v780: max of both sides + 1 gives read
// v782 paired with full v783.
// Merge of master read v782 with #10687 B read v782: max of both sides + 1 gives read v783
// paired with full v784.
// Merge of master read v787 / full v788 with #10687 B read v783 / full v784:
// max of both sides + 1 gives read v788 paired with full v789.
// #7314 AD3d EC2 r5: three-valued MSBuild conditions change C# membership answers; above master full v784 / read v783: read v785 pairs with full v786.
// Merge of master full v784 / read v783 (#10357) with this branch's full v786 / read v785: max of both sides + 1, past the open #7314 pairs, gives read v788 pairs with full v789.
// Merge of this batch's read v788 / full v789 with #7314 AD3d read v788 / full v789:
// max of both sides + 1 gives read v789 paired with full v790.
// #8430: grammar 0.23.9 parses namespace-body extern aliases as directives; above master full v784 / read v783: read v786 pairs with full v787.
// Merge of master full v784 / read v783 (#10357) with this branch's full v787 / read v786: max of both sides + 1, past the open #7314 pairs, gives read v789 pairs with full v790.
// Merge of this batch's read v789 / full v790 with #8430 read v789 / full v790:
// max of both sides + 1 gives read v790 paired with full v791.
// #10770 slice 1: typed method and operator results change retained call
// transfers: read v791 paired with full v792.
// #10761: read v784 pairs with full v785 for possible overload families.
// Merge of master full v788 / read v787 with #10761's full v785 / read v784:
// max of both sides + 1 gives read v788 paired with full v789.
// #10884: most-specific model overloads; merge of master read v787 / full v788 with
// this branch's read v784 / full v785: max of both sides + 1 gives read v788 paired with full v789.
// Merge of the batch's #10761 read v788 / full v789 with #10884 read v788 / full v789:
// max of both sides + 1 gives read v789 paired with full v790.
// Merge of master full v791 / read v790 with the batch's full v790 / read v789:
// max of both sides + 1 gives read v791 paired with full v792.
// Promotion merge of this batch's read v791 / full v792 with master's
// #10761/#10884 read v791 / full v792: max of both sides + 1 gives read v792 paired with full v793.
// #10802: log package identity and the unknown-argument guard: read v793 paired
// with full v794.
// Rust std Deref chains and their selected summary reads affect replayed answers.
// Merge above master full v793 / read v792 gives full v794 / read v793.
// #10846: unproven-conversion continuations change retained typestate answers:
// read v784 paired with full v785.
// Merge of master read v790 / full v791 with #10846 read v784 / full v785:
// max of both sides + 1 gives read v791 paired with full v792.
// Merge of this batch's read v792 / full v793 with #10846 read v791 / full v792:
// max of both sides + 1 gives read v793 paired with full v794.
// #10770 slice 2a: Self and model-backed result types: read v785 paired with
// full v786.
// #10770 slice 2b: generic result types.
// Merge of this batch's read v793 / full v794 with #10770 slice 2a read v785 / full v786:
// max of both sides + 1 gives read v794 paired with full v795.
// Merge receiver adjustment branch and current master: max + 1 gives v795.
// #10774+#10830: replay corrected Rust crate-context completion in call reads.
// #10774+#10830: above master read v790 / full v791: read v791 paired with full v792.
// Merge of master read v791 / full v792 with this branch's read v791 / full v792:
// max of both sides + 1 gives read v792 paired with full v793.
// Merge of master read v792 / full v793 with this branch: max of both sides + 1 gives read v793 paired with full v794.
// Merge of master's #10846/#10770 slice 2a read v794 / full v795 with this batch's #10774 read v793 / full v794:
// Merge of master read v794 / full v795 with #10770 slice 2b read v786 / full v787:
// Merge of master read v795 / full v796 (#10774) with #10770 slice 2b read v795 / full v796:
// Merge of master read v794 / full v795 with #10802 read v793 / full v794:
// Merge of master read v795 / full v796 (#10774) with #10802 read v795 / full v796:
// max of both sides + 1 gives read v796 paired with full v797.
// max of both sides + 1 gives read v795 paired with full v796.
// #10470: read completeness of JVM lookups changes for unchanged inputs; above master
// full v793 / read v792: full v794 / read v793.
// Promotion merge of this batch's read v793 / full v794 with master's
// #7314 M6a1: paired declared-type read identity.
// #10846/#10770 slice 2a/#10774 read v795 / full v796: max of both sides + 1
// gives read v796 paired with full v797.
// Promotion merge of this batch's read v796 / full v797 with master's
// #10470 read v796 / full v797: max of both sides + 1 gives read v797 paired with full v798.
// Merge of master read v796 / full v797 (#10470 batch) with #10802 read v796 / full v797:
// max of both sides + 1 gives read v797 paired with full v798.
// Batch merge of #10802 and #10770 slice 2c at master read v797 / full v798:
// max of both sides + 1 gives read v798 paired with full v799.
// #10770 slice 2c: operator Output result types: read v796 paired with full v797.
// Merge of #10770 slice 2b read v796 / full v797 (master #10774 merged) with
// slice 2c read v796 / full v797: max of both sides + 1 gives read v797 paired with full v798.
// #10770: alias expansion, paired with full v799.
// Promotion merge: read v800 paired with full v801, above master and sibling barrier.
// Merge of #10925 read v793 / full v794 with master read v794 / full v795: max of both sides + 1 gives read v795 paired with full v796.
// #10953: target-specific dependencies and destination library names change Rust
// route answers; the read half moves with the full half.
// Merge of master full v797 / read v796 and open c2 #10870 (v798/v797); taking c2's read v797 / full v798 with this branch: max of both sides + 1 gives read v798 paired with full v799.
// Merge of master full v798 / read v797 (#10946/#10961) and this branch's v799/v798; max is read v798 / full v799 with this branch: max of both sides + 1 gives read v799 paired with full v800.
// Merge of master full v799 / read v798 (#10955/#10957) and this branch's v800/v799; max is read v799 / full v800 with this branch: max of both sides + 1 gives read v800 paired with full v801.
// #9737 c2: above master read v782 / full v783: read v783 paired with full v784.
// Merge of master read v787 / full v788 with this branch's read v783 / full v784:
// Merge of #10774 read v791 / full v792 with this branch's read v788 / full v789:
// Merge of #10925 read v793 / full v794 with this branch: max of both sides + 1 gives read v794 paired with full v795.
// Merge of master read v794 / full v795 with this branch: max of both sides + 1 gives read v795 paired with full v796.
// Merge of master read v795 / full v796 with this branch: max of both sides + 1 gives read v796 paired with full v797.
// Merge of master read v796 / full v797 with this branch: max of both sides + 1 gives read v797 paired with full v798.
// Merge of master full v799 / read v798 (#10955/#10957) and open #10953 #10974 (v801/v800); above #10974's read v800 / full v801 with this branch: max of both sides + 1 gives read v801 paired with full v802.
// Merge of master full v801 / read v800 (#10953) and this branch's v802/v801; max is read v801 / full v802 with this branch: max of both sides + 1 gives read v802 paired with full v803.
// Final draft merge: parents v803/v802 and v801/v800; v805/v804 exceeds both,
// distinct from sibling barrier reservation v804/v803.
// Merge of master full v805 / read v804 and #10987's full v802 / read v801: max of both sides + 1 gives full v806 / read v805.
// Merge of master read v804 / full v805 (#11023) with this branch's read v802 / full v803: max of both sides + 1 gives read v805 paired with full v806.
// Merge of master full v806 / read v805 (#11023) and this branch's full v806 / read v805 (#10987): max of both sides + 1 gives full v807 / read v806.
// #9402: read v799 paired with full v800.
// Merge of master read v804 / full v805 with #9402 read v799 / full v800: max of both sides + 1 gives read v805 paired with full v806.
// Merge of master read v805 / full v806 with #9402 read v805 / full v806: max of both sides + 1 gives read v806 paired with full v807.
// Batch merge of two read v806 / full v807 sides (#10987/#11023 and #9402): max of both sides + 1 gives read v807 paired with full v808.
// #4307: selected std receiver-summary reads; read799 pairs with full800.
// #4307 final merge review: full802/read801 invalidates both parents
// (pre-merge800/799, master799/798) and exceeds the parallel alias pair801/800.
// #4307 last merge: parent assigned full804/read803 above prior802/801,
// master053bad7a40 full799/read798 and the parallel alias pair803/802.
// #4307 final submitted merge: owner selected full806/read805 above both parents
// (branch804/803 and master801/800) and the parallel alias pair805/804.
// #4307 alias merge: full807/read806 exceeds parents806/805 and805/804.
// #4307 mechanical merge: full808/read807 exceeds both parents807/806.
// #10989 M0: keyed collection cells: read v801 paired with full v802.
// Merge of master read v804 / full v805 with #10989 M0 read v801 / full v802: max of both sides + 1 gives read v805 paired with full v806.
// Merge of master read v806 / full v807 with #10989 M0 read v805 / full v806: max of both sides + 1 gives read v807 paired with full v808.
// Merge of #4307 full808/read807 and #10989 M0 full808/read807: max of both sides + 1 gives read808 paired with full809.
// Promotion merge of master full808/read807 with this batch's full809/read808: max of both sides + 1 gives read809 paired with full810.
// #10952: recorded Rust inventory lookups: read v799 paired with full v800.
// Merge of master read v800 / full v801 and this branch's #10952 read v799 / full v800: max of both sides + 1 gives read v801 paired with full v802.
// Merge of master read v805 / full v806 and this branch's #10952 read v801 / full v802: max of both sides + 1 gives read v806 paired with full v807.
// Merge of master workspace-read-behavior at full v808 / read v807 (#11056 and earlier) with this branch's #10952 v807/v806: max of both sides + 1 gives workspace-read-behavior v808.
// #11036: log macro shadow refusal: read v807 paired with full v808.
// Merge of master workspace-read-behavior at full v808 / read v807 (#11056 and earlier) with this branch's #11036 v808/v807: max of both sides + 1 gives read v808 paired with full v809.
// Batch merge of #10952 v809/v808 and #11036 v809/v808: max of both sides + 1 gives full v810 / read v809.
// #8296: C# model overloads select the exact-match member; above master v807/v806: read v807 paired with full v808.
// Merge of master read v807 / full v808 (#9402 batch) with #8296 read v807 / full v808: max of both sides + 1 gives read v808 paired with full v809.
// Batch merge of #10952/#11036 v810/v809 and #8296 v809/v808: max of both sides + 1 gives full v811 / read v810.
// #8298: a dotted C# type qualifier (`Serializer.Typeless.M()`) resolves its head through the using/alias ladder, so C# definitions and dispatch can name a nested external member; full v808 / read v807.
// Merge of master full v808 / read v807 (#9402 batch) with #8298 full v808 / read v807: max of both sides + 1 gives full v809 / read v808.
// Batch merge of #10952/#11036/#8296 v811/v810 and #8298 v809/v808: max of both sides + 1 gives full v812 / read v811.
// Promotion merge of master read v809 / full v810 with this batch's read v811 / full v812: max of both sides + 1 gives read v812 paired with full v813.
// #8299: C# receiver chains cross external members and typed-local residual
// conversions discharge at query time; master is read v806 / full v807.
// Merge of master read v812 / full v813 with #8299 read v807 / full v808: max of both sides + 1 gives read v813 paired with full v814.
// #9737 step d: above master read v812 / full v813: read v813 paired with full v814.
// Batch merge of #11075 read v813 / full v814 with #11079 read v813 / full v814: max of both sides + 1 gives read v814 paired with full v815.
// #11069: declaration_facts cache hits replay their fill's receipt; above master read v812 / full v813: read v813 paired with full v814.
// Batch merge of #11075/#11079 read v814 / full v815 with #11085 read v813 / full v814: max of both sides + 1 gives read v815 paired with full v816.
// #11060: standalone enumeration certificates and unplaced-module topology; above master read v812 / full v813: read v813 paired with full v814.
// #8297: C# model extension methods: read v813 paired with full v814.
// Merge of master read v813 / full v814 (#11060) with #8297 read v813 / full v814: max of both sides + 1 gives read v814 paired with full v815.
// Promotion merge of master read v813 / full v814 with this batch's read v815 / full v816: max of both sides + 1 gives read v816 paired with full v817.
// Promotion merge of master read v816 / full v817 with this batch's read v814 / full v815 (#11060, #8297): max of both sides + 1 gives read v817 paired with full v818.
// Model alias target expansion and #11043 share the full/read behavior rotation.
// Alias expansion merge: both parents full v810 / read v809; max + 1 gives full v811 / read v810.
// Final alias merge: parents full/read 811/810 and 813/812; max + 1 gives 814/813.
// Final model-alias submission merge: both parents full/read 814/813; max + 1 gives 815/814.
// Mechanical alias submission merge: parents 815/814 and 818/817; max + 1 gives full/read 819/818.
// Batch merge of master full v819 / read v818 (#8430 step 2) with this batch's
// full v819 / read v818 (#8297, model alias target expansion): max of both sides
// + 1 gives full v820 / read v819.
// #11111: certified-absent Rust module topology; above master read v817 / full v818: read v818 paired with full v819.
// Batch merge of the landed full v820 / read v819 with #11111's full v819 / read
// v818: max of both sides + 1 gives full v821 / read v820.
// #8430 step 3: paired with full v825 for alias-qualified consumer answers.
// Merge #10342 read v820 / full v821 with #8430 step 3 read v824 / full v825: max of both sides + 1 gives read v825 paired with full v826.
// Promotion merge of master read v820 / full v821 with this batch's read v825 / full v826: max of both sides + 1 gives read v826 paired with full v827.
// #11089: unready Rust inventories report candidate-scoped incompleteness; above master read v817 / full v818: read v818 paired with full v819.
// Merge of master read v818 / full v819 (#8430 step 2) with #11089 read v818 / full v819: max of both sides + 1 gives read v819 paired with full v820.
// Merge of master full v821 / read v820 (#11111 batch) with #11089 full v820 / read v819: max of both sides + 1 gives workspace-read-behavior v821.
// Batch promotion merge of master read v826 / full v827 with this batch's read v821 / full v822:
// max of both sides + 1 gives read v827 / full v828.
// #4967 C: moves with the full domain (Rust ? residual alias parameters).
// #7314 M6a1: declared types and global predefined aliases; full v821 / read v820, above master full v818 / read v817.
// Merge of #4967 C read v828 / full v829 with #7314 M6a1 read v828 / full v829:
// max of both sides + 1 gives read v829 paired with full v830.
// #4967 C slice 3: moves with the full domain (awaited residual typing).
// #10497: read v829 paired with full v830.
// #10497 merge: max(master full v833 / read v832, lane full v830 / read v829) + 1 = full v834 / read v833.
pub const WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN: &[u8] =
    // #7314 M10a0 part 2: read v818 paired with full v819.
    // #7314 M10a0 part 2: read v819 paired with full v820.
    // #11111 merge: full v821 / read v820.
    // #7314 M10a0 part 2 final merge: read v823 paired with full v824.
    // #10342 / #8430 step 3 merge: read v828 paired with full v829.
    // #11156/#11158 latest master read v827 paired with full v828; M6a1 reserves read v828/full v829; this lane assigned read v831/full v832.
    // Promotion merge: read v832 paired with full v833.
    // Merge of master read v832 / full v833 with #4967 C slice 3 read v830 / full v831:
    // max of both sides + 1 gives read v833 paired with full v834.
    // Promotion merge of our read v835 / full v836 with master read v833 / full v834:
    // max of both sides + 1 gives read v836 paired with full v837.
    // #10497 final master merge: max(master read v833, lane read v833) + 1 gives read v834, paired with full v835.
    // #10497 Ready merge: max(master read v833, lane read v834) + 1 gives read v835, paired with full v836.
    // Batch merge of master full v837 / read v836 with #10497 full v836 / read v835:
    // max of both sides + 1 gives full v838 / read v837.
    // #11173: read v833 paired with full v834.
    // Merge of master read v836 / full v837 with #11173 read v833 / full v834:
    // max of both sides + 1 gives read v837 paired with full v838.
    // Promotion merge of master read v837 / full v838 with this batch's read v837 / full v838:
    // max of both sides + 1 gives read v838 paired with full v839.
    b"bifrost-icfg-provider/workspace-read-behavior/v838";

#[cfg(test)]
mod domain_tests {
    use super::{
        WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN, WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN,
    };

    #[test]
    fn workspace_icfg_provider_domains_rotate_together() {
        let version = |domain: &[u8], prefix: &[u8]| {
            assert!(domain.starts_with(prefix));
            std::str::from_utf8(
                domain
                    .strip_prefix(prefix)
                    .unwrap()
                    .strip_prefix(b"/v")
                    .unwrap(),
            )
            .unwrap()
            .parse::<u64>()
            .unwrap()
        };

        let behavior = version(
            WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN,
            b"bifrost-icfg-provider/workspace-behavior",
        );
        let read = version(
            WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN,
            b"bifrost-icfg-provider/workspace-read-behavior",
        );
        assert_eq!(behavior, read + 1);
    }
}

/// Why one dispatch lookup could not be named by a replayable read key.
///
/// A summary that observes this status must fail closed instead of publishing
/// an apparently complete read set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DispatchReadUnattributedReason {
    /// The semantic call site has no exact retained source range.
    SourceRangeUnavailable,
    /// Contextual dispatch has no context-aware persisted replay question yet.
    CallContextUnavailable,
}

/// The replayable input read by one call-dispatch lookup, or the typed reason
/// that lookup cannot be attributed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Keep attributed reads inline; boxing adds an allocation per lookup.
pub enum DispatchReadAttribution {
    Attributed(ReadKey),
    Unattributed(DispatchReadUnattributedReason),
}

/// Whether this first authored non-return consumer has an unambiguous call
/// identity and immediate-invocation contract for `language`.
///
/// The external member key intentionally collapses same-arity overloads, and
/// an unmaterialized boundary does not carry async/generator invocation
/// semantics. Go has neither overloads nor deferred callable invocation at an
/// ordinary emitted call site. A supported `defer` emits on its cleanup route,
/// while a spawned call carries `DifferentTask` timing and never becomes a
/// synchronous body transfer. Broaden this predicate only with an equally
/// structured proof.
#[doc(hidden)]
pub const fn supports_authored_normal_continuation_absence(language: SemanticLanguage) -> bool {
    matches!(language, SemanticLanguage::Standard(Language::Go))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallTransfer {
    pub origin: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub callee_entry: ProgramPointHandle,
    /// Exact caller creation and captured slots for a during-call invocation.
    pub argument_callable: Option<Arc<ArgumentCallableProvenance>>,
    pub normal_continuation: ControlContinuation,
    pub exceptional_continuation: ControlContinuation,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallToReturnModel {
    Normal,
    Exceptional,
    NormalAndExceptional,
}

#[doc(hidden)]
pub const fn boundary_call_to_return_model(
    invocation_mode: CallInvocationMode,
    normal_continuation_absent: bool,
) -> CallToReturnModel {
    match (invocation_mode, normal_continuation_absent) {
        (CallInvocationMode::Detached, _) => CallToReturnModel::Normal,
        (CallInvocationMode::Ordinary, true) => CallToReturnModel::Exceptional,
        (CallInvocationMode::Ordinary, false) => CallToReturnModel::NormalAndExceptional,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnTransferKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnTransfer {
    pub origin: CallSiteHandle,
    pub callee_exit: ProgramPointHandle,
    pub continuation: ProgramPointHandle,
    pub kind: ReturnTransferKind,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

/// One procedure-local ICFG edge before a bounded call context assigns dense
/// snapshot node IDs.
///
/// Summary tabulation and bounded snapshot stitching consume the same owned
/// projection so call/return evidence cannot drift between the two backends.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcedureIcfgEdge {
    pub source: ProgramPointHandle,
    pub target: ProgramPointHandle,
    pub kind: IcfgEdgeKind,
    pub origin: Option<CallSiteHandle>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub boundary: Option<DispatchBoundaryKind>,
}

/// One procedure-local incomplete ICFG boundary before snapshot node
/// materialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcedureIcfgBoundary {
    pub at: ProgramPointHandle,
    pub origin: Option<CallSiteHandle>,
    pub kind: IcfgBoundaryKind,
}

/// Callee-local evidence from one entry to one normal or exceptional exit.
///
/// The profile deliberately excludes the evidence of any incoming call.
/// [`IcfgExitProfile::project_matched_return`] composes that caller-specific
/// evidence only when replaying a summary for an exact incoming call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcfgExitProfile {
    #[doc(hidden)]
    pub callee_entry: ProgramPointHandle,
    #[doc(hidden)]
    pub callee_exit: ProgramPointHandle,
    #[doc(hidden)]
    pub kind: ReturnTransferKind,
    #[doc(hidden)]
    pub gap_reason: Option<Box<str>>,
    #[doc(hidden)]
    pub matched_return_has_gaps: bool,
    #[doc(hidden)]
    pub matched_return_gap_reason: Option<Box<str>>,
    #[doc(hidden)]
    pub matched_return_gaps_are_implicit_abort_only: bool,
    // `SemanticOutcome` has no representation for a retained payload whose
    // quality is specifically truncated without attributing that truncation
    // to the current request budget. Keep the exact local quality so the
    // bounded snapshot adapter preserves its pre-extraction precedence when
    // it combines this profile with other semantic evidence.
    #[doc(hidden)]
    pub quality: SnapshotQuality,
}

impl IcfgExitProfile {
    pub fn callee_entry(&self) -> &ProgramPointHandle {
        &self.callee_entry
    }

    pub fn callee_exit(&self) -> &ProgramPointHandle {
        &self.callee_exit
    }

    pub const fn kind(&self) -> ReturnTransferKind {
        self.kind
    }

    /// Whether this exit contributes any gaps to the aggregate profile outcome.
    pub const fn has_aggregate_return_affecting_gaps(&self) -> bool {
        self.gap_reason.is_some()
    }

    /// Whether gaps weaken this exit's concrete matched-return projection.
    pub const fn has_matched_return_affecting_gaps(&self) -> bool {
        self.matched_return_has_gaps
    }

    /// Exact structured gaps contributing to the aggregate profile outcome.
    pub fn aggregate_return_affecting_gap_reason(&self) -> Option<&str> {
        self.gap_reason.as_deref()
    }

    /// Exact structured reason this exit cannot prove a complete matched return.
    pub fn matched_return_affecting_gap_reason(&self) -> Option<&str> {
        if !self.matched_return_has_gaps {
            None
        } else {
            self.matched_return_gap_reason
                .as_deref()
                .or(self.gap_reason.as_deref())
        }
    }

    /// Whether every gap weakening this matched return is an unlowered
    /// implicit-abort edge that its producer marked non-rejoining, with at
    /// least one such gap.
    ///
    /// The profile retains this structured classification because its rendered
    /// reason is diagnostic text, not an analysis interface. A caller may
    /// discharge these gaps only after proving that no abort route in its
    /// analyzed region runs user code.
    pub const fn matched_return_gaps_are_implicit_abort_only(&self) -> bool {
        self.matched_return_gaps_are_implicit_abort_only
    }

    /// Project this callee-local exit through one exact incoming call.
    pub fn project_matched_return(
        &self,
        incoming: &CallTransfer,
    ) -> Result<MatchedReturnProjection, SemanticProviderError> {
        project_matched_return(self, incoming)
    }
}

/// Exact result of matching one profiled callee exit to one incoming call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedReturnProjection {
    Edge {
        /// Exact return edge projected into the caller.
        edge: ProcedureIcfgEdge,
        /// Whether the exit profile is the only source weakening this edge,
        /// and all of its matched-return gaps are implicit aborts.
        implicit_abort_only: bool,
    },
    Absent,
    Boundary(ProcedureIcfgBoundary),
}

/// Procedure-local call-to-return edges and continuation boundaries projected
/// from one modeled dispatch boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallToReturnProjection {
    pub edges: Box<[ProcedureIcfgEdge]>,
    pub boundaries: Box<[ProcedureIcfgBoundary]>,
}

#[doc(hidden)]
pub type CallTransferCacheKey = (ProcedureHandle, CallSiteId, OracleCallContext);
#[doc(hidden)]
pub type ExitProfileCacheKey = (ProgramPointHandle, ProgramPointHandle);

/// One exact in-process semantic artifact allocation.
///
/// A validity key and materialization digest can describe independently
/// allocated identical rows, but prepared dispatch may return artifact-local
/// handles. Pointer identity keeps those handles inside their owner while the
/// strong reference prevents address reuse for the lifetime of the key.
#[derive(Clone)]
#[doc(hidden)]
pub struct ExactArtifactAllocation(
    #[doc(hidden)] pub Arc<crate::analyzer::semantic::SemanticArtifact>,
);

impl PartialEq for ExactArtifactAllocation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ExactArtifactAllocation {}

impl std::hash::Hash for ExactArtifactAllocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.0), state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgNodeKey {
    #[doc(hidden)]
    pub point: ProgramPointHandle,
    #[doc(hidden)]
    pub call_context: Box<[CallSiteHandle]>,
    #[doc(hidden)]
    pub argument_callable: Option<Arc<ArgumentCallableProvenance>>,
}

impl IcfgNodeKey {
    /// Construct one dense-snapshot node from a language-neutral program point
    /// and its exact outermost-to-innermost call context.
    pub fn new(point: ProgramPointHandle, call_context: Vec<CallSiteHandle>) -> Self {
        Self {
            point,
            call_context: call_context.into_boxed_slice(),
            argument_callable: None,
        }
    }

    /// Exact creation/capture association of the innermost argument closure
    /// whose body contains this node. Capture value transport remains a
    /// separate, explicitly incomplete consumer contract.
    pub fn argument_callable(&self) -> Option<&ArgumentCallableProvenance> {
        self.argument_callable.as_deref()
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub fn call_context(&self) -> &[CallSiteHandle] {
        &self.call_context
    }
}

macro_rules! dense_icfg_id {
    ($name:ident) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
            pub const fn new(raw: u32) -> Self {
                Self(raw)
            }

            pub const fn get(self) -> u32 {
                self.0
            }

            pub const fn index(self) -> usize {
                self.0 as usize
            }

            #[doc(hidden)]
            pub fn try_from_index(index: usize) -> Result<Self, SemanticProviderError> {
                u32::try_from(index).map(Self).map_err(|_| {
                    SemanticProviderError::internal(concat!(stringify!($name), " overflow"))
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

dense_icfg_id!(IcfgNodeId);
dense_icfg_id!(IcfgEdgeId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgEdgeKind {
    Intraprocedural(ControlEdgeKind),
    Call,
    NormalReturn,
    ExceptionalReturn,
    CallToNormalContinuation,
    CallToExceptionalContinuation,
}

impl IcfgEdgeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intraprocedural(kind) => kind.label(),
            Self::Call => "call_to_entry",
            Self::NormalReturn => "normal_return",
            Self::ExceptionalReturn => "exceptional_return",
            Self::CallToNormalContinuation => "call_to_normal_continuation",
            Self::CallToExceptionalContinuation => "call_to_exceptional_continuation",
        }
    }

    pub const fn sort_key(self) -> (u8, u8) {
        match self {
            Self::Intraprocedural(kind) => (0, kind.sort_rank()),
            Self::Call => (1, 0),
            Self::NormalReturn => (2, 0),
            Self::ExceptionalReturn => (3, 0),
            Self::CallToNormalContinuation => (4, 0),
            Self::CallToExceptionalContinuation => (5, 0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgEdge {
    pub source: IcfgNodeId,
    pub target: IcfgNodeId,
    pub kind: IcfgEdgeKind,
    pub origin: Option<CallSiteHandle>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub boundary: Option<DispatchBoundaryKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgLimitKind {
    CallDepth,
    Nodes,
    Edges,
}

impl IcfgLimitKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CallDepth => "call_depth_limit",
            Self::Nodes => "node_limit",
            Self::Edges => "edge_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IcfgBoundaryKind {
    Dispatch(DispatchBoundaryKind),
    Limit(IcfgLimitKind),
    Continuation {
        kind: CallContinuationKind,
        state: ControlContinuation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgBoundary {
    pub at: IcfgNodeId,
    pub origin: Option<CallSiteHandle>,
    pub kind: IcfgBoundaryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcfgSnapshotLimits {
    pub max_call_depth: u32,
    pub max_nodes: usize,
    pub max_edges: usize,
}

impl IcfgSnapshotLimits {
    pub fn new(
        max_call_depth: u32,
        max_nodes: usize,
        max_edges: usize,
    ) -> Result<Self, InvalidIcfgSnapshotLimits> {
        let limits = Self {
            max_call_depth,
            max_nodes,
            max_edges,
        };
        limits.validate()?;
        Ok(limits)
    }

    #[doc(hidden)]
    pub fn validate(self) -> Result<(), InvalidIcfgSnapshotLimits> {
        if self.max_call_depth == 0 || self.max_nodes == 0 || self.max_edges == 0 {
            return Err(InvalidIcfgSnapshotLimits);
        }
        Ok(())
    }
}

impl Default for IcfgSnapshotLimits {
    fn default() -> Self {
        Self {
            max_call_depth: 8,
            max_nodes: 50_000,
            max_edges: 200_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIcfgSnapshotLimits;

impl fmt::Display for InvalidIcfgSnapshotLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ICFG call-depth, node, and edge limits must be greater than zero")
    }
}

impl std::error::Error for InvalidIcfgSnapshotLimits {}

/// A bounded, dense, traversal-ready ICFG slice.
#[derive(Debug, Clone)]
pub struct IcfgSnapshot {
    nodes: Box<[IcfgNodeKey]>,
    edges: Box<[IcfgEdge]>,
    outgoing_offsets: Box<[u32]>,
    incoming_offsets: Box<[u32]>,
    incoming_edge_ids: Box<[IcfgEdgeId]>,
    boundaries: Box<[IcfgBoundary]>,
}

impl IcfgSnapshot {
    #[doc(hidden)]
    pub fn empty() -> Self {
        Self {
            nodes: Box::new([]),
            edges: Box::new([]),
            outgoing_offsets: Box::new([0]),
            incoming_offsets: Box::new([0]),
            incoming_edge_ids: Box::new([]),
            boundaries: Box::new([]),
        }
    }

    /// Validate and index an already bounded language-neutral ICFG projection.
    ///
    /// Edges are grouped stably by source node. Their caller-supplied order is
    /// preserved within each source row, which lets custom providers choose a
    /// deterministic traversal order without rebuilding compact adjacency
    /// indexes themselves.
    pub fn try_from_parts(
        nodes: Vec<IcfgNodeKey>,
        mut edges: Vec<IcfgEdge>,
        mut boundaries: Vec<IcfgBoundary>,
    ) -> Result<Self, SemanticProviderError> {
        edges.sort_by_key(|edge| edge.source);
        let node_count = nodes.len();
        let mut incoming_counts = vec![0_u32; node_count];
        for edge in &edges {
            validate_frozen_edge(edge, node_count)?;
            let count = &mut incoming_counts[edge.target.index()];
            *count = count
                .checked_add(1)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming row overflow"))?;
        }

        let mut outgoing_offsets = Vec::with_capacity(node_count.saturating_add(1));
        outgoing_offsets.push(0_u32);
        let mut cursor = 0usize;
        for source in 0..node_count {
            while cursor < edges.len() && edges[cursor].source.index() == source {
                cursor += 1;
            }
            outgoing_offsets.push(u32::try_from(cursor).map_err(|_| {
                SemanticProviderError::internal("ICFG outgoing offsets exceed u32")
            })?);
        }
        debug_assert_eq!(cursor, edges.len(), "ICFG edges are grouped by source");

        let mut incoming_offsets = Vec::with_capacity(node_count.saturating_add(1));
        incoming_offsets.push(0_u32);
        for count in incoming_counts {
            let next = incoming_offsets
                .last()
                .copied()
                .unwrap_or_default()
                .checked_add(count)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming offsets overflow"))?;
            incoming_offsets.push(next);
        }
        let mut incoming_edge_ids = vec![IcfgEdgeId::default(); edges.len()];
        let mut incoming_cursors = incoming_offsets[..node_count].to_vec();
        for (index, edge) in edges.iter().enumerate() {
            let target = edge.target.index();
            let destination = incoming_cursors[target] as usize;
            incoming_edge_ids[destination] = IcfgEdgeId::try_from_index(index)?;
            incoming_cursors[target] = incoming_cursors[target]
                .checked_add(1)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming cursor overflow"))?;
        }

        for boundary in &boundaries {
            if boundary.at.index() >= node_count {
                return Err(SemanticProviderError::internal(
                    "ICFG boundary has an out-of-range node",
                ));
            }
        }
        boundaries.sort_by_key(icfg_boundary_sort_key);
        boundaries.dedup();

        Ok(Self {
            nodes: nodes.into_boxed_slice(),
            edges: edges.into_boxed_slice(),
            outgoing_offsets: outgoing_offsets.into_boxed_slice(),
            incoming_offsets: incoming_offsets.into_boxed_slice(),
            incoming_edge_ids: incoming_edge_ids.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
        })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn node_ids(&self) -> impl ExactSizeIterator<Item = IcfgNodeId> + '_ {
        (0..self.nodes.len()).map(|index| {
            IcfgNodeId::try_from_index(index).expect("published ICFG node IDs fit in u32")
        })
    }

    pub fn nodes(&self) -> &[IcfgNodeKey] {
        &self.nodes
    }

    pub fn edges(&self) -> &[IcfgEdge] {
        &self.edges
    }

    pub fn boundaries(&self) -> &[IcfgBoundary] {
        &self.boundaries
    }

    pub fn node(&self, id: IcfgNodeId) -> Option<&IcfgNodeKey> {
        self.nodes.get(id.index())
    }

    pub fn edge(&self, id: IcfgEdgeId) -> Option<&IcfgEdge> {
        self.edges.get(id.index())
    }

    pub fn successor_edges(
        &self,
        node: IcfgNodeId,
    ) -> impl ExactSizeIterator<Item = (IcfgEdgeId, &IcfgEdge)> + '_ {
        let range = compact_row(&self.outgoing_offsets, node.index(), self.edges.len());
        range.map(|index| {
            let id = IcfgEdgeId::try_from_index(index).expect("published ICFG edge IDs fit in u32");
            (id, &self.edges[index])
        })
    }

    pub fn predecessor_edges(
        &self,
        node: IcfgNodeId,
    ) -> impl ExactSizeIterator<Item = (IcfgEdgeId, &IcfgEdge)> + '_ {
        let range = compact_row(
            &self.incoming_offsets,
            node.index(),
            self.incoming_edge_ids.len(),
        );
        range.map(|index| {
            let id = self.incoming_edge_ids[index];
            (id, &self.edges[id.index()])
        })
    }
}

fn compact_row(offsets: &[u32], row: usize, stored_len: usize) -> std::ops::Range<usize> {
    let Some((&start, &end)) = offsets.get(row).zip(offsets.get(row.saturating_add(1))) else {
        return stored_len..stored_len;
    };
    start as usize..end as usize
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct CallFrame {
    #[doc(hidden)]
    pub transfer: CallTransfer,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct TraversalKey {
    #[doc(hidden)]
    pub point: ProgramPointHandle,
    #[doc(hidden)]
    pub frames: Box<[CallFrame]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SnapshotQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    Truncated,
    Cancelled,
}

fn validate_frozen_edge(edge: &IcfgEdge, node_count: usize) -> Result<(), SemanticProviderError> {
    if edge.source.index() >= node_count {
        return Err(SemanticProviderError::internal(
            "ICFG edge has an out-of-range source",
        ));
    }
    if edge.target.index() >= node_count {
        return Err(SemanticProviderError::internal(
            "ICFG edge has an out-of-range target",
        ));
    }
    if !matches!(edge.kind, IcfgEdgeKind::Intraprocedural(_)) && edge.origin.is_none() {
        return Err(SemanticProviderError::internal(
            "interprocedural ICFG edge has no originating call site",
        ));
    }
    if edge.boundary.is_some()
        && !matches!(
            edge.kind,
            IcfgEdgeKind::CallToNormalContinuation | IcfgEdgeKind::CallToExceptionalContinuation
        )
    {
        return Err(SemanticProviderError::internal(
            "dispatch-boundary metadata is attached to a non-continuation ICFG edge",
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn node_work(key: &TraversalKey) -> SemanticWork {
    SemanticWork {
        program_points: 1,
        nested_entries: key.frames.len().saturating_add(2),
        ..SemanticWork::default()
    }
}

#[doc(hidden)]
pub fn merge_quality(current: SnapshotQuality, incoming: SnapshotQuality) -> SnapshotQuality {
    use crate::analyzer::semantic::icfg::SnapshotQuality::*;
    match (current, incoming) {
        (Cancelled, _) | (_, Cancelled) => Cancelled,
        (Truncated, _) | (_, Truncated) => Truncated,
        // The public outcome can carry only one unsupported capability. Use
        // stable capability order so aggregation is independent of traversal
        // and gap-emission order.
        (Unsupported(left), Unsupported(right)) => Unsupported(left.min(right)),
        (Unsupported(capability), _) | (_, Unsupported(capability)) => Unsupported(capability),
        (Unknown, _) | (_, Unknown) => Unknown,
        (Unproven, _) | (_, Unproven) => Unproven,
        (Ambiguous, _) | (_, Ambiguous) => Ambiguous,
        (Complete, Complete) => Complete,
    }
}

#[doc(hidden)]
pub fn icfg_edge_sort_key(edge: &IcfgEdge) -> (usize, (u8, u8), usize, u32) {
    (
        edge.source.index(),
        edge.kind.sort_key(),
        edge.target.index(),
        edge.origin
            .as_ref()
            .map_or(u32::MAX, |call| call.id().get()),
    )
}

fn icfg_boundary_sort_key(boundary: &IcfgBoundary) -> (usize, u32, u8) {
    (
        boundary.at.index(),
        boundary
            .origin
            .as_ref()
            .map_or(u32::MAX, |origin| origin.id().get()),
        match boundary.kind {
            IcfgBoundaryKind::Dispatch(_) => 0,
            IcfgBoundaryKind::Limit(_) => 1,
            IcfgBoundaryKind::Continuation { .. } => 2,
        },
    )
}

#[doc(hidden)]
pub fn call_binding_completeness(
    call: &SemanticCallSite,
    callee_values: &[SemanticValue],
    completeness: EvidenceCompleteness,
) -> (EvidenceCompleteness, usize) {
    let mut fixed_formals = 0usize;
    let mut defaulted_formals = 0usize;
    let mut has_rest_formal = false;
    for value in callee_values {
        match &value.kind {
            SemanticValueKind::Parameter {
                multiplicity: FormalMultiplicity::One,
                ..
            } => fixed_formals = fixed_formals.saturating_add(1),
            SemanticValueKind::Parameter {
                multiplicity: FormalMultiplicity::Rest(_),
                ..
            } => has_rest_formal = true,
            // IR validation admits at most one saved default per fixed formal,
            // and the call binder selects it for that formal when the call
            // omits it, so such a formal needs no actual.
            SemanticValueKind::DefaultArgument { .. } => {
                defaulted_formals = defaulted_formals.saturating_add(1)
            }
            _ => {}
        }
    }
    let required_formals = fixed_formals.saturating_sub(defaulted_formals);
    let bindings_complete = call.arguments.len() >= required_formals
        && (has_rest_formal || call.arguments.len() <= fixed_formals);
    if bindings_complete {
        return (completeness, 0);
    }

    let previous_reason_bytes = completeness_reason_bytes(&completeness);
    let completeness = EvidenceCompleteness::Partial(match completeness {
        EvidenceCompleteness::Complete => format!(
            "caller supplies {} arguments for {fixed_formals} fixed formal parameters; omitted/default or variadic binding effects are incomplete",
            call.arguments.len()
        )
        .into(),
        EvidenceCompleteness::Partial(existing) => format!(
            "{existing}; caller supplies {} arguments for {fixed_formals} fixed formal parameters; omitted/default or variadic binding effects are incomplete",
            call.arguments.len()
        )
        .into(),
    });
    let added_reason_bytes =
        completeness_reason_bytes(&completeness).saturating_sub(previous_reason_bytes);
    (completeness, added_reason_bytes)
}

#[doc(hidden)]
pub fn finish_snapshot_outcome(
    snapshot: IcfgSnapshot,
    quality: SnapshotQuality,
    exceeded: Option<SemanticBudgetExceeded>,
    work: SemanticWork,
) -> SemanticOutcome<IcfgSnapshot> {
    if quality == SnapshotQuality::Cancelled {
        return SemanticOutcome::Cancelled {
            partial: Some(snapshot),
            work,
        };
    }
    if let Some(exceeded) = exceeded {
        return SemanticOutcome::ExceededBudget {
            partial: Some(snapshot),
            exceeded,
            work,
        };
    }
    snapshot_quality_outcome(snapshot, quality, work)
}

fn snapshot_quality_outcome<T>(
    value: T,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> SemanticOutcome<T> {
    match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete { value, work },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: value,
            work,
        },
        SnapshotQuality::Unproven => SemanticOutcome::Unproven {
            partial: value,
            work,
        },
        SnapshotQuality::Unknown | SnapshotQuality::Truncated => SemanticOutcome::Unknown {
            partial: Some(value),
            work,
        },
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(value),
            work,
        },
        SnapshotQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(value),
            work,
        },
    }
}

#[doc(hidden)]
pub fn deferred_boundary_provenance(
    origin: &CallSiteHandle,
    boundary: &DispatchBoundaryKind,
    candidate_provenance: &[OracleRelationHandle],
    limits: OracleLimits,
) -> Result<(Box<[OracleRelationHandle]>, SemanticWork), SemanticProviderError> {
    let DispatchBoundaryKind::Deferred { target, .. } = boundary else {
        return Err(SemanticProviderError::internal(
            "deferred boundary provenance requires a deferred boundary identity",
        ));
    };
    let expected_owner = OracleRelationOwner::Dispatch(origin.clone());
    let mut evidence = Vec::<EvidenceHandle>::new();
    for relation in candidate_provenance {
        if relation.owner() != &expected_owner
            || relation.record().kind() != OracleRelationKind::DispatchCandidate
            || !matches!(
                relation.record().subject(),
                Some(OracleRelationSubject::DispatchCandidate(candidate))
                    if candidate.semantics().locator() == target
            )
        {
            return Err(SemanticProviderError::internal(
                "deferred transfer candidate has invalid dispatch provenance",
            ));
        }
        for retained in relation.record().evidence() {
            if !evidence.contains(retained) {
                evidence.push(retained.clone());
            }
        }
    }
    if evidence.is_empty() {
        return Err(SemanticProviderError::internal(
            "deferred transfer candidate has no semantic evidence",
        ));
    }
    let evidence_entries = evidence.len();
    let record = OracleRelationRecord::dispatch_boundary(boundary.clone(), evidence, limits)
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not project deferred dispatch-boundary provenance: {error}"
            ))
        })?;
    let arena =
        OracleRelationArena::new(expected_owner, vec![record], limits).map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not project deferred dispatch-boundary provenance: {error}"
            ))
        })?;
    let relation = arena
        .handle(OracleRelationId::new(0))
        .expect("deferred dispatch-boundary relation was inserted");
    let subject_work = semantic_locator_work(target);
    Ok((
        vec![relation].into_boxed_slice(),
        SemanticWork {
            // One payload handle, one arena record, and the record's evidence
            // array are retained independently by this projection. The exact
            // boundary subject additionally deep-clones its target locator.
            nested_entries: 2usize
                .saturating_add(evidence_entries)
                .saturating_add(subject_work.nested_entries),
            owned_text_bytes: subject_work.owned_text_bytes,
            ..subject_work
        },
    ))
}

#[doc(hidden)]
pub fn scoped_call_evaluation_gaps<'a>(
    procedure: &'a ProcedureHandle,
    call: &SemanticCallSite,
) -> Vec<&'a SemanticGap> {
    procedure
        .semantics()
        .gaps()
        .iter()
        .filter(|gap| call_evaluation_gap_applies(gap, call))
        .collect()
}

#[doc(hidden)]
pub fn call_evaluation_gap_applies(gap: &SemanticGap, call: &SemanticCallSite) -> bool {
    // A call-resolution gap asks a question this call's resolution and
    // binding answer, and those carry their own quality into the transfers
    // (#1989, #3757). It must not weaken the resolved transfers a second time.
    gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        && gap.discharge != SemanticGapDischarge::CallResolution
        && match gap.subject {
            SemanticGapSubject::Procedure => true,
            SemanticGapSubject::Point => gap.point == call.point,
            SemanticGapSubject::CallSite(call_site) => {
                call_site == call.id && gap.point == call.point
            }
            SemanticGapSubject::Value(_)
            | SemanticGapSubject::MemoryLocation(_)
            | SemanticGapSubject::Capture(_)
            | SemanticGapSubject::CallContinuation { .. }
            | SemanticGapSubject::AsyncContinuation { .. } => false,
        }
}

#[doc(hidden)]
pub fn materialize_exit_profile(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
    materialize_exit_profile_with_runtime_reads(callee_entry, callee_exit, &[], &[], request)
}

/// `discharged` gaps are answered by a query-time proof (runtime reads,
/// inert drops) and are not return gaps; `non_rejoining` gaps are aborts a
/// query-time proof shows to be non-rejoining exceptional exits.
#[doc(hidden)]
pub fn materialize_exit_profile_with_runtime_reads(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
    discharged_runtime_reads: &[crate::analyzer::semantic::SemanticGapId],
    non_rejoining: &[crate::analyzer::semantic::SemanticGapId],
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    if callee_entry.procedure() != callee_exit.procedure() {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile entry and exit belong to different procedures",
        ));
    }
    let procedure = callee_exit.procedure();
    let semantics = procedure.semantics();
    let kind = if callee_exit.id() == semantics.normal_exit_point() {
        ReturnTransferKind::Normal
    } else if callee_exit.id() == semantics.exceptional_exit_point() {
        ReturnTransferKind::Exceptional
    } else {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile requires a normal or exceptional procedure exit",
        ));
    };
    let point_count = semantics.points().len();
    let edge_count = semantics.control_edges().len();
    let gap_count = semantics.gaps().len();
    let traversal_steps = point_count
        .saturating_mul(2)
        .saturating_add(edge_count.saturating_mul(2))
        .saturating_add(gap_count);
    if !request.charge_execution_traversal(traversal_steps) {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let scan_work = SemanticWork {
        program_points: point_count.saturating_mul(2),
        control_edges: edge_count.saturating_mul(2),
        gaps: gap_count,
        nested_entries: point_count
            .saturating_mul(2)
            .saturating_add(edge_count.saturating_mul(2))
            .saturating_add(gap_count),
        ..SemanticWork::default()
    };
    request.budget.charge_work(scan_work);

    let algorithm_limits = CfgAlgorithmWork {
        node_visits: point_count.saturating_mul(2),
        edge_visits: edge_count.saturating_mul(2),
    };
    let mut algorithm_budget = CfgAlgorithmBudget::new(algorithm_limits);
    let mut algorithm_request =
        CfgAlgorithmRequest::new(&mut algorithm_budget, request.cancellation);
    let from_entry =
        match forward_reachability(semantics, callee_entry.id(), &mut algorithm_request) {
            Ok(reachable) => reachable,
            Err(CfgAlgorithmError::Cancelled { .. }) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: scan_work,
                });
            }
            Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
                unreachable!(
                    "precharged return-path traversal exceeded its complete-graph {} limit: \
                     attempted {}, limit {}, work {:?}",
                    exceeded.limit_kind.label(),
                    exceeded.attempted,
                    exceeded.limit,
                    exceeded.work
                );
            }
            Err(CfgAlgorithmError::InvalidNode(point)) => {
                unreachable!("validated procedure has an invalid entry point {point}");
            }
        };
    let to_exit = match reverse_reachability(semantics, callee_exit.id(), &mut algorithm_request) {
        Ok(reachable) => reachable,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: scan_work,
            });
        }
        Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
            unreachable!(
                "precharged return-path traversal exceeded its complete-graph {} limit: \
                 attempted {}, limit {}, work {:?}",
                exceeded.limit_kind.label(),
                exceeded.attempted,
                exceeded.limit,
                exceeded.work
            );
        }
        Err(CfgAlgorithmError::InvalidNode(point)) => {
            unreachable!("validated procedure has an invalid exit point {point}");
        }
    };
    debug_assert_eq!(algorithm_budget.limits(), algorithm_limits);

    let path_mask = from_entry
        .membership()
        .iter()
        .copied()
        .zip(to_exit.membership().iter().copied())
        .map(|(reachable, reaches_exit)| reachable && reaches_exit)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    // An implicit-exception gap whose abort paths run no user code cannot
    // move a value into or past the NORMAL exit: the missing edges only
    // remove abort paths, so they cannot weaken the normal profile (#1952).
    // The exceptional profile always keeps the gap: whether this procedure
    // can reach its exceptional exit decides whether a caller's handler is
    // reachable at all, and the missing edges are exactly that reachability.
    let abort_user_code =
        crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(semantics);
    let is_return_gap = |gap: &SemanticGap| {
        // A gap that declares a call-resolution discharge asks a question the
        // resolution and binding path always answers: an unresolved call
        // surfaces as a dispatch boundary, and a resolved callee that defers
        // evaluation carries its own procedure-level gap into its exit
        // profile and bindings (#1989). It must not weaken this caller's
        // exit profile a second time.
        if gap.discharge == SemanticGapDischarge::CallResolution
            || discharged_runtime_reads.contains(&gap.id)
        {
            return false;
        }
        let return_affecting = gap.impacts.contains(SemanticGapImpact::ReturnTransfer);
        let scoped_to_return_path = match gap.subject {
            SemanticGapSubject::Procedure => true,
            _ => path_mask.get(gap.point.index()).copied() == Some(true),
        };
        return_affecting
            && scoped_to_return_path
            && !(kind == ReturnTransferKind::Normal
                && crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                    gap,
                    abort_user_code,
                ))
    };
    let is_matched_return_gap =
        |gap: &SemanticGap| is_return_gap(gap) && gap_affects_matched_return(gap, kind);
    let mut return_gap_count = 0usize;
    let mut matched_return_gap_count = 0usize;
    let mut quality = SnapshotQuality::Complete;
    let mut gap_reason_bytes = 0usize;
    let mut matched_return_gap_reason_bytes = 0usize;
    let mut matched_return_gaps_are_implicit_abort_only = true;
    for gap in semantics.gaps() {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: scan_work,
            });
        }
        if !is_return_gap(gap) {
            continue;
        }
        quality = merge_quality(quality, semantic_gap_quality(gap));
        gap_reason_bytes = gap_reason_bytes
            .saturating_add(semantic_gap_reason_entry_bytes(gap, return_gap_count > 0));
        return_gap_count = return_gap_count.saturating_add(1);
        if is_matched_return_gap(gap) {
            matched_return_gaps_are_implicit_abort_only &= (gap.discharge
                == SemanticGapDischarge::NonRejoiningExceptionalExit
                || non_rejoining.contains(&gap.id))
                && crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                    gap, false,
                );
            matched_return_gap_reason_bytes = matched_return_gap_reason_bytes.saturating_add(
                semantic_gap_reason_entry_bytes(gap, matched_return_gap_count > 0),
            );
            matched_return_gap_count = matched_return_gap_count.saturating_add(1);
        }
    }
    // A route can be represented completely as topology while its edge
    // evidence remains unproven. The target-scoped gap does not necessarily
    // carry ReturnTransfer impact, so inspect the route itself.
    for edge in semantics.control_edges() {
        if path_mask[edge.source_point.index()]
            && path_mask[edge.target_point.index()]
            && !crate::analyzer::semantic::statement_entries::control_edge_proves_route(
                semantics,
                edge.evidence,
            )
        {
            quality = merge_quality(quality, SnapshotQuality::Unproven);
        }
    }
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: scan_work,
        });
    }
    let distinct_matched_reason_bytes =
        if matched_return_gap_count > 0 && matched_return_gap_count != return_gap_count {
            matched_return_gap_reason_bytes
        } else {
            0
        };
    let text_work = SemanticWork {
        owned_text_bytes: gap_reason_bytes.saturating_add(distinct_matched_reason_bytes),
        ..SemanticWork::default()
    };
    if let Err(exceeded) = request.budget.admit(text_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: scan_work,
        });
    }
    let total_work = scan_work.conservative_add(text_work);
    let gap_reason = if return_gap_count == 0 {
        None
    } else {
        let mut reason = String::with_capacity(gap_reason_bytes);
        let mut written = 0usize;
        for gap in semantics.gaps() {
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                });
            }
            if !is_return_gap(gap) {
                continue;
            }
            append_semantic_gap_reason_entry(&mut reason, gap, written > 0);
            written = written.saturating_add(1);
        }
        debug_assert_eq!(written, return_gap_count);
        debug_assert_eq!(reason.len(), gap_reason_bytes);
        Some(reason.into_boxed_str())
    };
    let matched_return_gap_reason =
        if matched_return_gap_count == 0 || matched_return_gap_count == return_gap_count {
            None
        } else {
            let mut reason = String::with_capacity(matched_return_gap_reason_bytes);
            let mut written = 0usize;
            for gap in semantics.gaps() {
                if request.cancellation.is_cancelled() {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: total_work,
                    });
                }
                if !is_matched_return_gap(gap) {
                    continue;
                }
                append_semantic_gap_reason_entry(&mut reason, gap, written > 0);
                written = written.saturating_add(1);
            }
            debug_assert_eq!(written, matched_return_gap_count);
            debug_assert_eq!(reason.len(), matched_return_gap_reason_bytes);
            Some(reason.into_boxed_str())
        };
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: total_work,
        });
    }
    let profile = IcfgExitProfile {
        callee_entry: callee_entry.clone(),
        callee_exit: callee_exit.clone(),
        kind,
        gap_reason,
        matched_return_has_gaps: matched_return_gap_count > 0,
        matched_return_gap_reason,
        matched_return_gaps_are_implicit_abort_only: matched_return_gap_count > 0
            && matched_return_gaps_are_implicit_abort_only,
        quality,
    };
    Ok(exit_profile_outcome(profile, quality, total_work))
}

fn semantic_gap_reason_entry_bytes(gap: &SemanticGap, has_prior: bool) -> usize {
    usize::from(has_prior)
        .saturating_mul(2)
        .saturating_add(gap.kind.label().len())
        .saturating_add(1)
        .saturating_add(gap.capability.label().len())
        .saturating_add(2)
        .saturating_add(gap.detail.len())
}

fn append_semantic_gap_reason_entry(reason: &mut String, gap: &SemanticGap, has_prior: bool) {
    if has_prior {
        reason.push_str("; ");
    }
    reason.push_str(gap.kind.label());
    reason.push(' ');
    reason.push_str(gap.capability.label());
    reason.push_str(": ");
    reason.push_str(&gap.detail);
}

#[doc(hidden)]
pub fn gap_affects_matched_return(gap: &SemanticGap, kind: ReturnTransferKind) -> bool {
    // An unsupported exceptional alternative does not weaken the explicitly
    // represented normal route through the same operation. Unknown exceptional
    // behavior can still make that concrete route itself uncertain.
    kind != ReturnTransferKind::Normal
        || gap.capability != SemanticCapability::ExceptionalControlFlow
        || gap.kind != SemanticGapKind::Unsupported
}

fn exit_profile_outcome(
    profile: IcfgExitProfile,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> SemanticOutcome<IcfgExitProfile> {
    snapshot_quality_outcome(profile, quality, work)
}

#[doc(hidden)]
pub fn semantic_gap_quality(gap: &SemanticGap) -> SnapshotQuality {
    match gap.kind {
        SemanticGapKind::Ambiguous => SnapshotQuality::Ambiguous,
        SemanticGapKind::Unsupported => SnapshotQuality::Unsupported(gap.capability),
        SemanticGapKind::ExceededBudget => SnapshotQuality::Truncated,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven => SnapshotQuality::Unproven,
    }
}

#[doc(hidden)]
pub fn deferred_invocation_kind(
    properties: crate::analyzer::semantic::ProcedureProperties,
) -> DeferredInvocationKind {
    match (properties.is_async, properties.is_generator) {
        (true, true) => DeferredInvocationKind::AsyncGenerator,
        (true, false) => DeferredInvocationKind::Async,
        (false, true) => DeferredInvocationKind::Generator,
        (false, false) => DeferredInvocationKind::LanguageDefined,
    }
}

pub(crate) fn project_matched_return(
    exit: &IcfgExitProfile,
    incoming: &CallTransfer,
) -> Result<MatchedReturnProjection, SemanticProviderError> {
    if incoming.callee != *exit.callee_exit.procedure()
        || incoming.callee_entry != exit.callee_entry
    {
        return Err(SemanticProviderError::internal(
            "ICFG incoming call does not match the profiled callee entry",
        ));
    }

    let (continuation_kind, destination) = match exit.kind {
        ReturnTransferKind::Normal => (CallContinuationKind::Normal, incoming.normal_continuation),
        ReturnTransferKind::Exceptional => (
            CallContinuationKind::Exceptional,
            incoming.exceptional_continuation,
        ),
    };
    match destination {
        ControlContinuation::Target(point) => {
            let (proof, completeness) = return_evidence(exit, incoming);
            let implicit_abort_only = exit.matched_return_gaps_are_implicit_abort_only
                && matches!(&incoming.proof, ProofStatus::Proven)
                && matches!(&incoming.completeness, EvidenceCompleteness::Complete);
            let continuation = incoming
                .origin
                .procedure()
                .point_handle(point)
                .ok_or_else(|| SemanticProviderError::internal("return continuation is stale"))?;
            Ok(MatchedReturnProjection::Edge {
                edge: ProcedureIcfgEdge {
                    source: exit.callee_exit.clone(),
                    target: continuation,
                    kind: match exit.kind {
                        ReturnTransferKind::Normal => IcfgEdgeKind::NormalReturn,
                        ReturnTransferKind::Exceptional => IcfgEdgeKind::ExceptionalReturn,
                    },
                    origin: Some(incoming.origin.clone()),
                    proof,
                    completeness,
                    boundary: None,
                },
                implicit_abort_only,
            })
        }
        ControlContinuation::Absent => Ok(MatchedReturnProjection::Absent),
        state => Ok(MatchedReturnProjection::Boundary(ProcedureIcfgBoundary {
            at: exit.callee_exit.clone(),
            origin: Some(incoming.origin.clone()),
            kind: IcfgBoundaryKind::Continuation {
                kind: continuation_kind,
                state,
            },
        })),
    }
}

fn return_evidence(
    exit: &IcfgExitProfile,
    incoming: &CallTransfer,
) -> (ProofStatus, EvidenceCompleteness) {
    let Some(gap_reason) = exit.matched_return_affecting_gap_reason() else {
        return (incoming.proof.clone(), incoming.completeness.clone());
    };
    let proof = match &incoming.proof {
        ProofStatus::Proven => ProofStatus::Unproven(
            format!(
                "callee-exit evidence does not prove this {:?} completion returns to its caller: {gap_reason}",
                exit.kind
            )
            .into(),
        ),
        ProofStatus::Unproven(existing) => {
            ProofStatus::Unproven(format!("{existing}; {gap_reason}").into())
        }
    };
    let completeness = match &incoming.completeness {
        EvidenceCompleteness::Complete => EvidenceCompleteness::Partial(
            format!("the callee exit has exact return-affecting semantic gaps: {gap_reason}")
                .into(),
        ),
        EvidenceCompleteness::Partial(existing) => EvidenceCompleteness::Partial(
            format!("{existing}; return-affecting gaps: {gap_reason}").into(),
        ),
    };
    (proof, completeness)
}

pub fn invoked_call_at(
    point: &ProgramPointHandle,
) -> Result<Option<CallSiteId>, SemanticProviderError> {
    let semantic_point = point
        .procedure()
        .semantics()
        .point(point.id())
        .ok_or_else(|| SemanticProviderError::internal("ICFG point handle is stale"))?;
    Ok(semantic_point
        .events
        .iter()
        .find_map(|event| match event.effect {
            crate::analyzer::semantic::SemanticEffect::Invoke { call_site } => Some(call_site),
            _ => None,
        }))
}

/// Validate provider-owned exit evidence before either ICFG backend caches it.
pub fn validate_exit_profile(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
    profile: &IcfgExitProfile,
) -> Result<(), SemanticProviderError> {
    if profile.callee_entry() != callee_entry {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile entry does not match the requested entry",
        ));
    }
    if profile.callee_exit() != callee_exit {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile exit does not match the requested exit",
        ));
    }
    Ok(())
}

pub fn is_call_scaffolding(
    edge: &crate::analyzer::semantic::ControlEdge,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> bool {
    matches!(
        (edge.kind, call.normal_continuation),
        (ControlEdgeKind::Normal, ControlContinuation::Target(target)) if edge.target_point == target
    ) || matches!(
        (edge.kind, call.exceptional_continuation),
        (ControlEdgeKind::Exceptional, ControlContinuation::Target(target)) if edge.target_point == target
    )
}
