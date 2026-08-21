//! Callable-signature rows projected from the persisted signature contract
//! (issue #1478, Milestone 2).
//!
//! A call site's shape (Milestone 1) is only half of overload selection. The
//! other half is the declaration side: for each candidate callable, how many
//! arguments it requires, how many it accepts, whether the last parameter
//! repeats, how many type parameters it declares, what must be bound in
//! receiver position, and what it returns. Bifrost already computes every one
//! of those facts at extraction time and persists them as `SignatureMetadata`
//! and `CallableArity`; until now nothing projected them into a queryable row.
//!
//! This module is a pure projection of that persisted contract. It never
//! re-parses a declaration and never reads source text: every field here is
//! read from a `SignatureMetadata` value the analyzer already published, so a
//! warm cache and a cold run answer identically by construction.
//!
//! Two honesty rules follow the receiver-outcome and call-shape discipline:
//!
//! - One input declaration always produces at least one row. A declaration
//!   whose language publishes no signature metadata still gets a row whose
//!   [`SignatureCoverage`] says `unrecorded`, so an empty relation can never be
//!   read as "this callable takes no arguments".
//! - A fact the adapter did not record is absent, never defaulted. Arity is
//!   absent when the language records none; the receiver contract is absent
//!   when the adapter never inspected the callable's modifiers, because "not
//!   static" and "nobody looked" are different answers.
//!
//! A declaration with several persisted signature entries -- an overload set
//! that shares one fully qualified name, or a C++ declaration and its
//! definition -- produces one row per entry, ordered by the persisted ordinal.
//! That is what makes an overload set queryable: two rows with equal
//! `total_arity` and different parameter rows are exactly the same-arity
//! overload pair a resolver has to discriminate.
//!
//! Not represented yet: a curried or contextual parameter *list* sequence. The
//! persisted contract flattens every parameter list of a declaration into one
//! ordered parameter vector and records arity for the first list only, and
//! neither the fact arena nor any other persisted structure segments them.
//! Segmentation is therefore a persisted-contract addition, not a derivation,
//! and it is deliberately left out of this slice rather than reconstructed by
//! scanning the rendered signature label for parentheses.

use crate::analyzer::semantic::LengthDelimitedDigest;
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CodeUnit, CodeUnitType, SignatureMetadata,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    DeclarationRole, ReceiverContract, SignatureCoverage,
};

const CALLABLE_SIGNATURE_ID_DOMAIN: &[u8] = b"bifrost.code_query.callable_signature.v1";
const SIGNATURE_PARAMETER_ID_DOMAIN: &[u8] = b"bifrost.code_query.signature_parameter.v1";

/// The mandatory row for one persisted signature entry of one declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallableSignatureRow {
    /// Stable row id, domain-separated over the declaration's canonical
    /// identity digest and the persisted entry ordinal.
    pub id: String,
    /// Zero-based position of this entry among the declaration's persisted
    /// signature entries. An overload set shares a declaration identity and is
    /// separated by this ordinal.
    pub ordinal: usize,
    pub coverage: SignatureCoverage,
    pub role: DeclarationRole,
    /// The rendered signature header the adapter published, when it published
    /// one. Retained as evidence for a human reading a finding; never parsed.
    pub label: Option<String>,
    /// The adapter's own arity, absent when it recorded none.
    pub arity: Option<CallableArity>,
    /// Declared type parameters (generic arity). A language that records none
    /// reports zero, which is why `coverage` is read alongside it.
    pub generic_arity: usize,
    /// What must be bound in receiver position, when the persisted facts
    /// decide it. Absent when the adapter never inspected modifiers and the
    /// declaration is neither an extension nor a constructor.
    pub receiver_contract: Option<ReceiverContract>,
    /// The written return type, when the adapter recorded one.
    pub return_type: Option<String>,
    /// Whether this entry is a declaration without a body (a header, an
    /// abstract member, or an interface member).
    pub declaration_only: bool,
    /// How many parameter rows this signature produces.
    pub parameter_count: usize,
}

/// One ordered parameter of one persisted signature entry.
///
/// The byte offsets are positions inside the signature *label*, not inside the
/// declaring file: that is the only anchor the persisted contract carries for
/// a parameter, and naming it honestly keeps a consumer from joining it to a
/// file range it does not describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParameterRow {
    pub id: String,
    /// The owning [`CallableSignatureRow::id`].
    pub signature_id: String,
    /// Zero-based position in the declared parameter list.
    pub parameter_index: usize,
    /// The parameter label the adapter recorded.
    pub label: String,
    /// The declared type spelling, when the adapter records per-parameter
    /// types. A spelling is a discriminator inside an already bounded
    /// candidate set, never a resolved type identity.
    pub declared_type: Option<String>,
    /// Whether this parameter sits beyond the required count, so a call may
    /// omit it. Absent when the signature records no arity.
    pub optional: Option<bool>,
    /// Whether this is the repeating (variadic) trailing parameter. Absent
    /// when the signature records no arity.
    pub repeated: Option<bool>,
    pub label_start_byte: usize,
    pub label_end_byte: usize,
}

/// One declaration's complete projected signature evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallableSignatureReport {
    pub signature: CallableSignatureRow,
    pub parameters: Vec<SignatureParameterRow>,
}

/// Project every persisted signature entry of `unit` into rows.
///
/// `declaration_id` is the caller's canonical identity digest for the
/// declaration, which anchors every row id here; `entries` is the analyzer's
/// own `signature_metadata` answer, in persisted order. An empty slice still
/// yields exactly one report, whose coverage is `unrecorded`.
pub fn callable_signature_reports(
    declaration_id: &str,
    unit: &CodeUnit,
    entries: &[SignatureMetadata],
) -> Vec<CallableSignatureReport> {
    if entries.is_empty() {
        return vec![CallableSignatureReport {
            signature: CallableSignatureRow {
                id: signature_row_id(declaration_id, 0),
                ordinal: 0,
                coverage: SignatureCoverage::Unrecorded,
                role: role_of(unit, None),
                label: None,
                arity: None,
                generic_arity: 0,
                receiver_contract: None,
                return_type: None,
                declaration_only: false,
                parameter_count: 0,
            },
            parameters: Vec::new(),
        }];
    }
    entries
        .iter()
        .enumerate()
        .map(|(ordinal, metadata)| report_for_entry(declaration_id, unit, ordinal, metadata))
        .collect()
}

fn report_for_entry(
    declaration_id: &str,
    unit: &CodeUnit,
    ordinal: usize,
    metadata: &SignatureMetadata,
) -> CallableSignatureReport {
    let signature_id = signature_row_id(declaration_id, ordinal);
    let arity = metadata.callable_arity();
    let declared_types = metadata.callable_parameter_types();
    let last_index = metadata.parameters().len().saturating_sub(1);
    let parameters = metadata
        .parameters()
        .iter()
        .enumerate()
        .map(|(parameter_index, parameter)| {
            let mut digest = LengthDelimitedDigest::new(SIGNATURE_PARAMETER_ID_DOMAIN);
            digest.push(signature_id.as_bytes());
            digest.push(&parameter_index.to_le_bytes());
            SignatureParameterRow {
                id: digest.finish().to_string(),
                signature_id: signature_id.clone(),
                parameter_index,
                label: parameter.label().to_owned(),
                declared_type: declared_types
                    .and_then(|types| types.get(parameter_index))
                    .cloned(),
                optional: arity.map(|arity| parameter_index >= arity.required()),
                repeated: arity.map(|arity| arity.is_repeated() && parameter_index == last_index),
                label_start_byte: parameter.start_byte(),
                label_end_byte: parameter.end_byte(),
            }
        })
        .collect::<Vec<_>>();
    CallableSignatureReport {
        signature: CallableSignatureRow {
            id: signature_id,
            ordinal,
            coverage: if arity.is_some() {
                SignatureCoverage::Exact
            } else {
                SignatureCoverage::ArityUnrecorded
            },
            role: role_of(unit, Some(metadata)),
            label: Some(metadata.label().to_owned()),
            arity,
            generic_arity: metadata.type_parameters().len(),
            receiver_contract: receiver_contract_of(unit, metadata),
            return_type: metadata.return_type_text().map(str::to_owned),
            declaration_only: metadata.is_declaration_only(),
            parameter_count: parameters.len(),
        },
        parameters,
    }
}

fn signature_row_id(declaration_id: &str, ordinal: usize) -> String {
    let mut digest = LengthDelimitedDigest::new(CALLABLE_SIGNATURE_ID_DOMAIN);
    digest.push(declaration_id.as_bytes());
    digest.push(&ordinal.to_le_bytes());
    digest.finish().to_string()
}

/// What the declaration is. The persisted constructor flag wins over the unit
/// kind, because a constructor is a callable whose unit kind is `Function`;
/// otherwise a callable owned by a type scope is a method and one owned by a
/// package, module, or no scope is a free function.
fn role_of(unit: &CodeUnit, metadata: Option<&SignatureMetadata>) -> DeclarationRole {
    match unit.kind() {
        CodeUnitType::Function => {
            if metadata.is_some_and(SignatureMetadata::callable_is_constructor) {
                DeclarationRole::Constructor
            } else if unit.owner_is_type_scope() {
                DeclarationRole::Method
            } else {
                DeclarationRole::Function
            }
        }
        CodeUnitType::Field => DeclarationRole::Field,
        CodeUnitType::Class => DeclarationRole::Class,
        CodeUnitType::Module => DeclarationRole::Module,
        CodeUnitType::Macro => DeclarationRole::Macro,
        CodeUnitType::FileScope => DeclarationRole::FileScope,
    }
}

/// What must be bound in receiver position for this callable to apply.
///
/// Decidable without reading modifiers in exactly two cases: an extension
/// callable states the type it extends, and a constructor binds no receiver.
/// Everything else needs the adapter to have inspected the declaration's
/// modifier nodes, because a callable that is not recorded static is not
/// thereby an instance member -- it may simply be a language whose adapter
/// never looked. That case reports no contract at all rather than guessing.
fn receiver_contract_of(unit: &CodeUnit, metadata: &SignatureMetadata) -> Option<ReceiverContract> {
    if !unit.is_callable() {
        return None;
    }
    if metadata.extension_receiver_type().is_some() {
        return Some(ReceiverContract::Extension);
    }
    if metadata.callable_is_constructor() {
        return Some(ReceiverContract::None);
    }
    if !metadata.callable_modifiers_recorded() {
        return None;
    }
    if metadata.callable_is_static() {
        return Some(ReceiverContract::StaticOrCompanion);
    }
    if unit.owner_is_type_scope() {
        Some(ReceiverContract::Instance)
    } else {
        Some(ReceiverContract::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use brokk_bifrost_core::analyzer::model::{ParameterMetadata, ProjectFile};
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

    fn unit(owner: &str, name: &str) -> CodeUnit {
        let file = ProjectFile::new(std::env::temp_dir(), "Main.java");
        let interner = segment_interner();
        let mut fq = FqName::new();
        if !owner.is_empty() {
            fq.push(interner.intern(owner, SegmentKind::Type));
        }
        fq.push(interner.intern(name, SegmentKind::Member));
        CodeUnit::from_fq(file, CodeUnitType::Function, fq, 0, None, false)
    }

    fn parameters(labels: &[&str]) -> Vec<ParameterMetadata> {
        labels
            .iter()
            .enumerate()
            .map(|(index, label)| ParameterMetadata::new(*label, index, index + label.len()))
            .collect()
    }

    /// A declaration with no persisted metadata still produces exactly one
    /// row, and that row says the signature is unrecorded rather than empty.
    #[test]
    fn missing_metadata_still_produces_one_mandatory_row() {
        let reports = callable_signature_reports("decl", &unit("Widget", "run"), &[]);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].signature.coverage, SignatureCoverage::Unrecorded);
        assert_eq!(reports[0].signature.arity, None);
        assert!(reports[0].parameters.is_empty());
    }

    /// An overload set shares one declaration identity and separates into one
    /// row per persisted entry, each with its own parameter rows. Equal total
    /// arity with different parameter type spellings is exactly the pair a
    /// resolver has to discriminate.
    #[test]
    fn overload_entries_produce_distinct_rows_at_equal_arity() {
        let first = SignatureMetadata::new("void f(int a, String b)", parameters(&["a", "b"]))
            .with_callable_arity(CallableArity::exact(2))
            .with_callable_parameter_types(vec!["int".to_owned(), "String".to_owned()]);
        let second = SignatureMetadata::new("void f(String a, int b)", parameters(&["a", "b"]))
            .with_callable_arity(CallableArity::exact(2))
            .with_callable_parameter_types(vec!["String".to_owned(), "int".to_owned()]);
        let reports = callable_signature_reports("decl", &unit("Widget", "f"), &[first, second]);
        assert_eq!(reports.len(), 2);
        assert_ne!(reports[0].signature.id, reports[1].signature.id);
        assert_eq!(
            reports[0].signature.arity.map(CallableArity::total),
            reports[1].signature.arity.map(CallableArity::total)
        );
        assert_eq!(
            reports[0]
                .parameters
                .iter()
                .map(|parameter| parameter.declared_type.clone())
                .collect::<Vec<_>>(),
            vec![Some("int".to_owned()), Some("String".to_owned())]
        );
        assert_eq!(
            reports[1]
                .parameters
                .iter()
                .map(|parameter| parameter.declared_type.clone())
                .collect::<Vec<_>>(),
            vec![Some("String".to_owned()), Some("int".to_owned())]
        );
    }

    /// A default argument makes `required < total`, and the parameter beyond
    /// the required count is optional.
    #[test]
    fn defaults_produce_an_arity_range_with_optional_parameters() {
        let metadata = SignatureMetadata::new("void f(int a, int b = 1)", parameters(&["a", "b"]))
            .with_callable_arity(CallableArity::new(1, 2, false));
        let reports = callable_signature_reports("decl", &unit("Widget", "f"), &[metadata]);
        let signature = &reports[0].signature;
        assert_eq!(signature.coverage, SignatureCoverage::Exact);
        assert_eq!(signature.arity.map(CallableArity::required), Some(1));
        assert_eq!(signature.arity.map(CallableArity::total), Some(2));
        assert_eq!(reports[0].parameters[0].optional, Some(false));
        assert_eq!(reports[0].parameters[1].optional, Some(true));
        assert_eq!(reports[0].parameters[1].repeated, Some(false));
    }

    /// A variadic signature marks the trailing parameter repeated, and only
    /// the trailing one.
    #[test]
    fn variadics_mark_only_the_trailing_parameter_repeated() {
        let metadata =
            SignatureMetadata::new("void f(int a, int... rest)", parameters(&["a", "rest"]))
                .with_callable_arity(CallableArity::new(1, 2, true));
        let reports = callable_signature_reports("decl", &unit("Widget", "f"), &[metadata]);
        assert_eq!(reports[0].parameters[0].repeated, Some(false));
        assert_eq!(reports[0].parameters[1].repeated, Some(true));
        assert_eq!(
            reports[0].signature.arity.map(CallableArity::is_repeated),
            Some(true)
        );
    }

    /// Arity that nobody recorded is absent, and the coverage says so instead
    /// of publishing a zero that reads like a proven empty parameter list.
    #[test]
    fn unrecorded_arity_is_absent_rather_than_zero() {
        let metadata = SignatureMetadata::new("def f(a, b)", parameters(&["a", "b"]));
        let reports = callable_signature_reports("decl", &unit("Widget", "f"), &[metadata]);
        assert_eq!(
            reports[0].signature.coverage,
            SignatureCoverage::ArityUnrecorded
        );
        assert_eq!(reports[0].signature.arity, None);
        assert_eq!(reports[0].parameters[0].optional, None);
        assert_eq!(reports[0].parameters[0].repeated, None);
    }

    /// The receiver contracts a persisted signature can decide are distinct,
    /// and an adapter that never read modifiers reports none at all.
    #[test]
    fn receiver_contracts_are_distinct_and_never_guessed() {
        let owned = unit("Widget", "run");
        let free = unit("", "run");

        let unread = SignatureMetadata::new("void run()", Vec::new());
        assert_eq!(
            callable_signature_reports("decl", &owned, &[unread])[0]
                .signature
                .receiver_contract,
            None
        );

        let instance = SignatureMetadata::new("void run()", Vec::new()).with_callable_modifiers(
            false,
            false,
            DeclaredVisibility::Public,
        );
        assert_eq!(
            callable_signature_reports("decl", &owned, &[instance])[0]
                .signature
                .receiver_contract,
            Some(ReceiverContract::Instance)
        );

        let statik = SignatureMetadata::new("static void run()", Vec::new())
            .with_callable_modifiers(true, false, DeclaredVisibility::Public);
        assert_eq!(
            callable_signature_reports("decl", &owned, &[statik])[0]
                .signature
                .receiver_contract,
            Some(ReceiverContract::StaticOrCompanion)
        );

        let constructor = SignatureMetadata::new("Widget()", Vec::new()).with_callable_modifiers(
            false,
            true,
            DeclaredVisibility::Public,
        );
        let constructor_report = &callable_signature_reports("decl", &owned, &[constructor])[0];
        assert_eq!(
            constructor_report.signature.role,
            DeclarationRole::Constructor
        );
        assert_eq!(
            constructor_report.signature.receiver_contract,
            Some(ReceiverContract::None)
        );

        let extension = SignatureMetadata::new("fun Widget.run()", Vec::new())
            .with_extension_receiver_type(Some("Widget"));
        assert_eq!(
            callable_signature_reports("decl", &free, &[extension])[0]
                .signature
                .receiver_contract,
            Some(ReceiverContract::Extension)
        );
    }

    /// Row identities are deterministic across two derivations of the same
    /// input, which is what makes a warm run and a cold run comparable.
    #[test]
    fn row_identities_are_deterministic() {
        let metadata = SignatureMetadata::new("void f(int a)", parameters(&["a"]))
            .with_callable_arity(CallableArity::exact(1));
        let declaration = unit("Widget", "f");
        let first =
            callable_signature_reports("decl", &declaration, std::slice::from_ref(&metadata));
        let second =
            callable_signature_reports("decl", &declaration, std::slice::from_ref(&metadata));
        assert_eq!(first, second);
    }
}
