//! Resolver-proven per-actual applicability facts (#2724).
//!
//! Binding and conversion completeness are separate: matching a formal slot
//! does not establish its type. This query-local relation consumes the selected
//! declaration and the shared formal layout. It never selects an overload.

mod java;
mod typescript;

pub use java::ExternalConversionIdentity;

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::{
    formal_parameter_slots_for_owner_with_nodes, parameter_owner_for_range,
};
use crate::analyzer::semantic::{
    LengthDelimitedDigest, StableDigest, TransferKind, TransferOperation, ValuePreservation,
    ValueTransfer,
};
use crate::analyzer::usages::call_binding::{
    CallBindingKind, CallBindingMapping, CallBindingReport, CallBindingRow,
};
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaPrimitive {
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeScriptPrimitive {
    Boolean,
    Number,
    String,
    BigInt,
    Symbol,
}

/// Resolved identities, rather than parser-derived names or displayed types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedConversionType {
    JavaPrimitive(JavaPrimitive),
    TypeScriptPrimitive(TypeScriptPrimitive),
    Declaration(CodeUnit),
    /// Exact artifact/model declaration identity supplied by the resolver.
    External {
        identity: ExternalConversionIdentity,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionKind {
    JavaIdentity,
    JavaPrimitiveWidening,
    JavaBoxing,
    JavaUnboxing,
    TypeScriptIdentity,
    TypeScriptStructuralAssignability,
}

impl ConversionKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::JavaIdentity => "java_identity",
            Self::JavaPrimitiveWidening => "java_primitive_widening",
            Self::JavaBoxing => "java_boxing",
            Self::JavaUnboxing => "java_unboxing",
            Self::TypeScriptIdentity => "typescript_identity",
            Self::TypeScriptStructuralAssignability => "typescript_structural_assignability",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionUnknown {
    UnsupportedLanguage,
    UnresolvedSignature,
    UnresolvedSourceType,
    UnresolvedTargetType,
    AmbiguousBinding,
    GenericSubstitution,
    UnsupportedConversion,
    UnsupportedExpression,
    /// Another actual prevents establishing applicability of this signature.
    SignatureApplicability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentTypeConversion {
    pub source: ResolvedConversionType,
    pub target: ResolvedConversionType,
    pub kind: ConversionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionProof {
    ResolverProven,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionCompleteness {
    /// Exhaustive for this actual/formal typing relation, not runtime behavior.
    CompleteForPair,
    Unknown(ConversionUnknown),
}

/// The result is complete only for conversion typing of this actual/formal
/// pair. It does not close dispatch, exceptions (including null unboxing),
/// wrapper allocation/cache identity, or the enclosing procedure's behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallArgumentConversion {
    pub site_id: String,
    pub selected_signature: Option<String>,
    pub target: Option<CodeUnit>,
    pub argument_id: Option<String>,
    pub formal_index: Option<usize>,
    pub result: Result<ArgumentTypeConversion, ConversionUnknown>,
    pub proof: ConversionProof,
    pub completeness: ConversionCompleteness,
    operation_id: Option<StableDigest>,
}

impl CallArgumentConversion {
    pub(crate) fn unknown(
        row: &CallBindingRow,
        target: Option<&CodeUnit>,
        signature: Option<&str>,
        reason: ConversionUnknown,
    ) -> Self {
        Self {
            site_id: row.site_id.clone(),
            selected_signature: signature.map(str::to_owned),
            target: target.cloned(),
            argument_id: row.argument_id.clone(),
            formal_index: row.formal_index,
            result: Err(reason),
            proof: ConversionProof::Unknown,
            completeness: ConversionCompleteness::Unknown(reason),
            operation_id: None,
        }
    }

    /// A proven result has exhaustive typing evidence for this pair; unknown
    /// results retain the typed prerequisite that was missing.
    pub fn is_proven(&self) -> bool {
        self.result.is_ok()
    }

    pub fn operation(&self) -> Option<TransferOperation> {
        self.operation_id
            .map(TransferOperation::CallArgumentConversion)
    }

    /// Consumer seam for value-flow lowering. Identity and structural reference
    /// adjustments preserve aliasing and therefore emit no identity barrier.
    /// The caller must separately retain exceptional and allocation uncertainty.
    pub fn transfer(&self) -> Option<ValueTransfer> {
        let conversion = self.result.as_ref().ok()?;
        let kind = match conversion.kind {
            ConversionKind::JavaBoxing => TransferKind::Boxing,
            ConversionKind::JavaUnboxing => TransferKind::Unboxing,
            ConversionKind::JavaPrimitiveWidening => {
                use JavaPrimitive::{Double, Float, Int, Long};
                let changing = matches!(
                    (&conversion.source, &conversion.target),
                    (
                        ResolvedConversionType::JavaPrimitive(Int | Long),
                        ResolvedConversionType::JavaPrimitive(Float)
                    ) | (
                        ResolvedConversionType::JavaPrimitive(Long),
                        ResolvedConversionType::JavaPrimitive(Double)
                    )
                );
                TransferKind::Conversion {
                    preservation: if changing {
                        ValuePreservation::Changing
                    } else {
                        ValuePreservation::Preserving
                    },
                }
            }
            ConversionKind::JavaIdentity
            | ConversionKind::TypeScriptIdentity
            | ConversionKind::TypeScriptStructuralAssignability => return None,
        };
        Some(ValueTransfer {
            kind,
            operation: self
                .operation()
                .expect("proven conversions own an operation"),
        })
    }

    fn establish(&mut self, conversion: ArgumentTypeConversion) {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.call_argument_conversion.v1");
        digest.push(self.site_id.as_bytes());
        digest.push(
            self.selected_signature
                .as_ref()
                .expect("selected signature")
                .as_bytes(),
        );
        digest.push(
            self.target
                .as_ref()
                .expect("selected target")
                .declaration_id()
                .as_str()
                .as_bytes(),
        );
        digest.push(self.argument_id.as_ref().expect("source actual").as_bytes());
        digest.push(&(self.formal_index.expect("bound formal") as u64).to_be_bytes());
        for identity in [&conversion.source, &conversion.target] {
            match identity {
                ResolvedConversionType::JavaPrimitive(primitive) => {
                    digest.push(b"java_primitive");
                    digest.push(&[*primitive as u8]);
                }
                ResolvedConversionType::TypeScriptPrimitive(primitive) => {
                    digest.push(b"typescript_primitive");
                    digest.push(&[*primitive as u8]);
                }
                ResolvedConversionType::Declaration(unit) => {
                    digest.push(b"declaration");
                    digest.push(unit.declaration_id().as_str().as_bytes());
                }
                ResolvedConversionType::External { identity } => {
                    digest.push(b"external");
                    digest.push(identity.digest().as_bytes());
                }
            }
        }
        digest.push(conversion.kind.label().as_bytes());
        self.operation_id = Some(digest.finish());
        self.result = Ok(conversion);
        self.proof = ConversionProof::ResolverProven;
        self.completeness = ConversionCompleteness::CompleteForPair;
    }
}

type IndexedConversionProof = (usize, Result<ArgumentTypeConversion, ConversionUnknown>);

struct ConversionSource {
    source: String,
    tree: tree_sitter::Tree,
}

/// One indexed source/tree per file, scoped to the caller's query snapshot.
#[derive(Default)]
pub struct CallConversionCache {
    sources: HashMap<ProjectFile, Option<Arc<ConversionSource>>>,
}

impl CallConversionCache {
    fn source(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Option<Arc<ConversionSource>> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                let source = analyzer.indexed_source(file)?;
                let tree = parse_tree_for_language(file, language_for_file(file), &source)?;
                Some(Arc::new(ConversionSource { source, tree }))
            })
            .clone()
    }

    /// Resolve conversion typing for a selected source signature and project
    /// only an exact call/target/signature/actual/formal join into binding rows.
    pub fn populate(
        &mut self,
        analyzer: &dyn IAnalyzer,
        report: &mut CallBindingReport,
        signature: Option<&str>,
    ) {
        let language = language_for_file(&report.file);
        let prerequisite = if !matches!(language, Language::Java | Language::TypeScript) {
            Err(ConversionUnknown::UnsupportedLanguage)
        } else {
            self.prove(analyzer, report, signature, language)
        };
        report.conversion_facts = report
            .rows
            .iter()
            .map(|row| {
                CallArgumentConversion::unknown(
                    row,
                    report.target.as_ref(),
                    signature,
                    prerequisite
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(ConversionUnknown::AmbiguousBinding),
                )
            })
            .collect();
        if let Ok(proofs) = prerequisite {
            for (index, proof) in proofs {
                match proof {
                    Ok(proof) => report.conversion_facts[index].establish(proof),
                    Err(reason) => {
                        report.conversion_facts[index].result = Err(reason);
                        report.conversion_facts[index].completeness =
                            ConversionCompleteness::Unknown(reason);
                    }
                }
            }
        }
        project_conversion_facts(report, signature);
    }

    fn prove(
        &mut self,
        analyzer: &dyn IAnalyzer,
        report: &CallBindingReport,
        signature: Option<&str>,
        language: Language,
    ) -> Result<Vec<IndexedConversionProof>, ConversionUnknown> {
        signature.ok_or(ConversionUnknown::UnresolvedSignature)?;
        let target = report
            .target
            .as_ref()
            .ok_or(ConversionUnknown::UnresolvedSignature)?;
        let metadata = analyzer.signature_metadata(target);
        let [metadata] = metadata.as_slice() else {
            return Err(ConversionUnknown::UnresolvedSignature);
        };
        if !metadata.type_parameters().is_empty() {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let source = self
            .source(analyzer, &report.file)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let formal_source = self
            .source(analyzer, target.source())
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let ranges = analyzer.ranges_of(target);
        let [range] = ranges.as_slice() else {
            return Err(ConversionUnknown::UnresolvedSignature);
        };
        let owner = parameter_owner_for_range(language, formal_source.tree.root_node(), range)
            .ok_or(ConversionUnknown::UnresolvedSignature)?;
        // Generic owners require substitution even when the method itself is
        // nongeneric. The bounded adapters deliberately do not erase a type.
        let mut enclosing = Some(owner);
        while let Some(node) = enclosing {
            if node.child_by_field_name("type_parameters").is_some() {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            enclosing = node.parent();
        }
        if language == Language::TypeScript
            && let Some(parameters) = owner.child_by_field_name("parameters")
        {
            let mut cursor = parameters.walk();
            if parameters.named_children(&mut cursor).any(|parameter| {
                parameter
                    .child_by_field_name("pattern")
                    .is_some_and(|pattern| pattern.kind() == "this")
            }) {
                // An explicit compile-time receiver adds an applicability
                // constraint that ordinary actual/formal typing cannot prove.
                return Err(ConversionUnknown::SignatureApplicability);
            }
        }
        let slots =
            formal_parameter_slots_for_owner_with_nodes(language, owner, &formal_source.source)
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let ordinary: Vec<_> = slots.iter().filter(|(slot, _)| !slot.receiver).collect();
        let mut proofs = Vec::new();
        for (index, row) in report.rows.iter().enumerate() {
            if row.argument_id.is_none()
                || matches!(
                    row.binding_kind,
                    Some(CallBindingKind::Receiver | CallBindingKind::Implicit)
                )
            {
                continue;
            }
            let proof = (|| {
                if row.mapping != CallBindingMapping::Exact
                    || row.binding_kind != Some(CallBindingKind::Positional)
                {
                    return Err(ConversionUnknown::AmbiguousBinding);
                }
                let (slot, formal) = ordinary
                    .get(
                        row.formal_index
                            .ok_or(ConversionUnknown::AmbiguousBinding)?,
                    )
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                if slot.variadic.is_some() {
                    return Err(ConversionUnknown::UnsupportedConversion);
                }
                let actual = source
                    .tree
                    .root_node()
                    .named_descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
                    .filter(|node| node.byte_range() == (row.range.start_byte..row.range.end_byte))
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                if actual.has_error()
                    || actual.is_missing()
                    || formal.has_error()
                    || formal.is_missing()
                {
                    return Err(ConversionUnknown::UnsupportedExpression);
                }
                match language {
                    Language::Java => java::prove_argument(
                        analyzer,
                        &report.file,
                        actual,
                        &source.source,
                        target.source(),
                        *formal,
                        &formal_source.source,
                    ),
                    Language::TypeScript => typescript::prove_argument(
                        analyzer,
                        &report.file,
                        actual,
                        &source.source,
                        target.source(),
                        *formal,
                        &formal_source.source,
                    ),
                    _ => unreachable!("language capability checked before type resolution"),
                }
            })();
            proofs.push((index, proof));
        }
        // A type-compatible pair cannot borrow a signature whose applicability
        // is still unestablished at another actual.
        let missing_formal = ordinary.iter().enumerate().any(|(index, _)| {
            !report
                .rows
                .iter()
                .any(|row| row.formal_index == Some(index) && row.argument_id.is_some())
        });
        if missing_formal
            || proofs.iter().any(|(_, proof)| proof.is_err())
            || report
                .rows
                .iter()
                .any(|row| row.terminal || row.mapping != CallBindingMapping::Exact)
        {
            for (_, proof) in &mut proofs {
                if proof.is_ok() {
                    *proof = Err(ConversionUnknown::SignatureApplicability);
                }
            }
        }
        Ok(proofs)
    }
}

/// Presentation is an exact identity join, independent of fact ordering. A
/// fact for another signature, target, actual or formal cannot label this row.
pub fn project_conversion_facts(report: &mut CallBindingReport, signature: Option<&str>) {
    let mut by_binding = HashMap::default();
    for fact in &report.conversion_facts {
        if fact.target != report.target || fact.selected_signature.as_deref() != signature {
            continue;
        }
        let previous = by_binding.insert(
            (
                fact.site_id.as_str(),
                fact.argument_id.as_deref(),
                fact.formal_index,
            ),
            fact,
        );
        assert!(
            previous.is_none(),
            "one conversion result per exact actual/formal pair"
        );
    }
    for row in &mut report.rows {
        row.conversion = by_binding
            .get(&(
                row.site_id.as_str(),
                row.argument_id.as_deref(),
                row.formal_index,
            ))
            .and_then(|fact| fact.result.as_ref().ok())
            .map(|proof| proof.kind.label().to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::call_binding::CallBindingCoverage;
    use crate::analyzer::{CodeUnitType, Range};

    fn report() -> CallBindingReport {
        let file = ProjectFile::new(std::env::temp_dir(), "Conversions.java");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "Conversions.take");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 0,
            end_line: 0,
        };
        let rows: Vec<_> = (0..2)
            .map(|index| CallBindingRow {
                id: format!("binding-{index}"),
                site_id: "call".to_owned(),
                group_id: Some("group".to_owned()),
                argument_id: Some(format!("actual-{index}")),
                actual_index: Some(index),
                actual_name: None,
                formal_index: Some(index),
                formal_name: None,
                binding_kind: Some(CallBindingKind::Positional),
                mapping: CallBindingMapping::Exact,
                reason: None,
                conversion: None,
                range,
                terminal: false,
            })
            .collect();
        let conversion_facts = rows
            .iter()
            .map(|row| {
                let mut fact = CallArgumentConversion::unknown(
                    row,
                    Some(&target),
                    Some("signature"),
                    ConversionUnknown::UnresolvedSourceType,
                );
                fact.establish(ArgumentTypeConversion {
                    source: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int),
                    target: ResolvedConversionType::JavaPrimitive(if row.formal_index == Some(0) {
                        JavaPrimitive::Long
                    } else {
                        JavaPrimitive::Int
                    }),
                    kind: if row.formal_index == Some(0) {
                        ConversionKind::JavaPrimitiveWidening
                    } else {
                        ConversionKind::JavaIdentity
                    },
                });
                fact
            })
            .collect();
        CallBindingReport {
            file,
            site_id: "call".to_owned(),
            site_ast_id: "ast".to_owned(),
            range,
            target: Some(target),
            coverage: CallBindingCoverage::Exhaustive,
            actual_count: 2,
            bound_count: 2,
            rows,
            conversion_facts,
        }
    }

    #[test]
    fn projection_is_order_independent_and_reference_identity_has_no_transfer_barrier() {
        let mut expected = report();
        project_conversion_facts(&mut expected, Some("signature"));
        let mut reordered = report();
        reordered.conversion_facts.reverse();
        project_conversion_facts(&mut reordered, Some("signature"));
        assert_eq!(expected.rows, reordered.rows);
        let widening = expected.conversion_facts[0]
            .transfer()
            .expect("widening transfer");
        assert_eq!(
            widening.kind,
            TransferKind::Conversion {
                preservation: ValuePreservation::Preserving
            }
        );
        assert_eq!(
            Some(widening.operation),
            expected.conversion_facts[0].operation()
        );
        assert!(expected.conversion_facts[1].transfer().is_none());
        assert_ne!(
            expected.conversion_facts[0].operation(),
            expected.conversion_facts[1].operation()
        );
    }

    #[test]
    fn wrong_signature_target_actual_formal_and_site_cannot_borrow_a_conversion() {
        let original = report();
        for dimension in 0..5 {
            let mut changed = original.clone();
            let fact = &mut changed.conversion_facts[0];
            match dimension {
                0 => fact.selected_signature = Some("another-signature".to_owned()),
                1 => fact.target = None,
                2 => fact.argument_id = Some("another-actual".to_owned()),
                3 => fact.formal_index = Some(99),
                4 => fact.site_id = "another-call".to_owned(),
                _ => unreachable!(),
            }
            project_conversion_facts(&mut changed, Some("signature"));
            assert!(
                changed.rows[0].conversion.is_none(),
                "dimension {dimension}"
            );
            assert_eq!(changed.rows[1].conversion.as_deref(), Some("java_identity"));
        }
    }

    #[test]
    fn widening_that_rounds_values_does_not_claim_value_preservation() {
        let mut report = report();
        report.conversion_facts[0].establish(ArgumentTypeConversion {
            source: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int),
            target: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Float),
            kind: ConversionKind::JavaPrimitiveWidening,
        });
        let witness = (1_i32 << 24) + 1;
        assert_ne!((witness as f32) as i32, witness);
        assert_eq!(
            report.conversion_facts[0]
                .transfer()
                .expect("widening")
                .kind,
            TransferKind::Conversion {
                preservation: ValuePreservation::Changing
            }
        );
    }
}
