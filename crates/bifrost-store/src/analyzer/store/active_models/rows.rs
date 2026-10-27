//! Query-local merge of decoded postings and catalog rows in publication order.

use super::*;
use crate::analyzer::store::model_catalog::semantic_catalog_question;
use rusqlite::{Row, named_params};

pub(super) fn record_json<T: serde::de::DeserializeOwned>(row: &Row<'_>) -> rusqlite::Result<T> {
    let json: String = row.get("record_json")?;
    serde_json::from_str(&json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            row.as_ref()
                .column_index("record_json")
                .expect("record JSON column"),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

impl ResolvedActiveSemanticModels {
    pub(super) fn has_row_backed_shards(&self) -> bool {
        self.shards.iter().any(|shard| shard.decoded.is_none())
    }

    /// Both inputs have the same shard/record order. A shard has one backing,
    /// so its local SQL row keys and decoded offsets never need comparison.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn merged_question<T>(
        &self,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        bindings: impl rusqlite::Params,
        posting: Option<&Vec<RecordAddress>>,
        decoded: impl Fn(&ActiveSemanticModelShard, usize) -> Option<&Arc<T>>,
        decode: impl Fn(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Vec<ActivatedSemanticModelRecord<T>> {
        let reader = self
            .source_reader
            .as_ref()
            .expect("row-backed active set has its reader");
        let rows = semantic_catalog_question(
            statement_name,
            key,
            reader.raw_rows(statement, bindings, &self.shards, |row| {
                Ok((row.get::<_, i64>("record_key")?, Arc::new(decode(row)?)))
            }),
        );
        let mut rows = rows
            .into_iter()
            .filter_map(|row| {
                let index = self
                    .shards
                    .iter()
                    .position(|s| Arc::ptr_eq(&s.metadata, &row.shard))
                    .expect("active row metadata belongs to this publication");
                let shard = &self.shards[index];
                shard.decoded.is_none().then(|| {
                    (
                        (index, row.record.0),
                        ActivatedSemanticModelRecord {
                            shard: Arc::clone(shard),
                            record: Arc::clone(&row.record.1),
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|(key, _)| *key);
        rows.dedup_by_key(|(key, _)| *key);
        let decoded = posting.into_iter().flatten().map(|address| {
            let shard = &self.shards[address.shard as usize];
            debug_assert!(
                shard.decoded.is_some(),
                "only decoded shards have matcher postings"
            );
            (
                (address.shard as usize, i64::from(address.record)),
                ActivatedSemanticModelRecord {
                    record: Arc::clone(
                        decoded(shard, address.record as usize)
                            .expect("decoded posting addresses its record"),
                    ),
                    shard: Arc::clone(shard),
                },
            )
        });
        merge_ordered_semantic_results(decoded, rows, |a, b| a.0.cmp(&b.0))
            .into_iter()
            .map(|(_, record)| record)
            .collect()
    }

    pub(super) fn type_question(
        &self,
        statement_name: &str,
        statement: &str,
        key: &str,
        bindings: impl rusqlite::Params,
        posting: Option<&Vec<RecordAddress>>,
    ) -> Vec<ActivatedSemanticModelRecord<TypeFact>> {
        self.merged_question(
            statement_name,
            statement,
            key,
            bindings,
            posting,
            |shard, index| shard.decoded().payload().declaration_facts()?.0.get(index),
            record_json,
        )
        .into_iter()
        .filter(|r| !r.shard.guard_excludes(r.record.guard.as_ref()))
        .collect()
    }

    pub(super) fn member_question(
        &self,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        bindings: impl rusqlite::Params,
        posting: Option<&Vec<RecordAddress>>,
    ) -> Vec<ActivatedSemanticModelRecord<MemberFact>> {
        self.merged_question(
            statement_name,
            statement,
            key,
            bindings,
            posting,
            |shard, index| shard.decoded().payload().declaration_facts()?.1.get(index),
            record_json,
        )
        .into_iter()
        .filter(|r| !r.shard.guard_excludes(r.record.guard.as_ref()))
        .collect()
    }

    pub(super) fn relation_question(
        &self,
        statement_name: &str,
        statement: &str,
        id: &str,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<RelationFact> {
        resolve_records(self.merged_question(
            statement_name,
            statement,
            id,
            named_params! { ":id": id },
            posting,
            |shard, index| shard.decoded().payload().declaration_facts()?.2.get(index),
            |row| {
                Ok(RelationFact {
                    id: row.get("record_id")?,
                    from: row.get("from_id")?,
                    to: row.get("to_id")?,
                    relation_kind: serde_json::from_value(serde_json::Value::String(
                        row.get("relation_kind")?,
                    ))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            row.as_ref()
                                .column_index("relation_kind")
                                .expect("relation kind column"),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                })
            },
        ))
    }

    pub(super) fn rule_question(
        &self,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        bindings: impl rusqlite::Params,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<GeneratorRule> {
        resolve_records(self.merged_question(
            statement_name,
            statement,
            key,
            bindings,
            posting,
            |shard, index| shard.decoded().payload().generator_rules()?.get(index),
            record_json,
        ))
    }
}

pub(super) fn distinct_addresses<T>(
    mut records: Vec<ActivatedSemanticModelRecord<T>>,
) -> Vec<ActivatedSemanticModelRecord<T>> {
    records.dedup_by(|a, b| Arc::ptr_eq(&a.shard, &b.shard) && Arc::ptr_eq(&a.record, &b.record));
    records
}

impl ResolvedActiveSemanticModels {
    pub(super) fn shard_records<T: serde::de::DeserializeOwned>(
        &self,
        shard: &ActiveSemanticModelShard,
        statement_name: &str,
        statement: &str,
    ) -> Vec<Arc<T>> {
        let identity = shard
            .row_store
            .expect("row-backed shard has its catalog identity");
        let source = match identity.database {
            CatalogShardDatabase::Durable => "durable",
            CatalogShardDatabase::Session => "session",
        };
        semantic_catalog_question(
            statement_name,
            identity,
            self.source_reader
                .as_ref()
                .expect("row-backed set has its reader")
                .raw_records(
                    statement,
                    named_params! { ":source_db": source, ":shard_key": identity.shard_key },
                    &self.shards,
                ),
        )
        .into_iter()
        .map(|record| record.record)
        .collect()
    }

    pub(super) fn shard_payload<T: serde::de::DeserializeOwned>(
        &self,
        shard: &ActiveSemanticModelShard,
        statement_name: &str,
        statement: &str,
    ) -> Option<Arc<T>> {
        let mut records = self.shard_records(shard, statement_name, statement);
        debug_assert!(records.len() <= 1, "one whole-payload row per shard");
        records.pop()
    }

    pub(super) fn has_family(
        &self,
        shard: &ActiveSemanticModelShard,
        family: brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily,
    ) -> bool {
        let identity = shard
            .row_store
            .expect("row-backed shard has its catalog identity");
        semantic_catalog_question(
            "PAYLOAD_FAMILY_PRESENCE",
            (identity, family),
            self.source_reader
                .as_ref()
                .expect("row-backed set has its reader")
                .payload_family_presence(identity, family),
        )
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn summary_owner_spellings(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> Vec<String> {
        let realm = semantic_pack_realm(key.language);
        let mut names = HashSet::default();
        for declaration in self.all_type_records_named(key.owner) {
            if declaration.shard.manifest.extraction.is_some()
                && semantic_pack_realm(&declaration.shard.manifest.language) == realm
            {
                names.insert(declaration.record.name.clone());
                names.extend(declaration.record.aliases.iter().cloned());
            }
        }
        names.remove(key.owner);
        let mut names = names.into_iter().collect::<Vec<_>>();
        names.sort_unstable();
        names.push(key.owner.to_owned());
        names
    }

    pub(super) fn summary_member_records(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
        owners: &[String],
    ) -> Vec<ActivatedSemanticModelRecord<CompiledProcedureSummary>> {
        let realm = semantic_pack_realm(key.language);
        let mut posting = Vec::new();
        for owner in owners {
            if let Some(shapes) = self
                .indexes
                .procedure_summaries_by_member
                .get(realm)
                .and_then(|owners| owners.get(owner))
                .and_then(|members| members.get(key.member))
            {
                posting.extend(
                    shapes
                        .fixed
                        .values()
                        .chain(shapes.variadic.values())
                        .chain(shapes.optional_fixed.values())
                        .flatten()
                        .copied(),
                );
            }
        }
        posting.sort_by_key(|address| (address.shard, address.record));
        posting.dedup_by_key(|address| (address.shard, address.record));
        self.merged_question("SUMMARY_MEMBER", statements::SUMMARY_MEMBER,
            (key.language, owners, key.member, key.has_receiver),
            named_params! { ":realm": realm, ":owners": serde_json::to_string(owners).expect("owner spellings serialize"),
                ":member": key.member, ":receiver": key.has_receiver }, Some(&posting),
            |shard, index| shard.decoded().payload().procedure_summaries()?.get(index), record_json)
            .into_iter().filter(|r| r.record.target.has_receiver == key.has_receiver).collect()
    }

    pub(super) fn applicable_summary_records(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
        owners: &[String],
        actual_counts: &[u32],
    ) -> Vec<ActivatedSemanticModelRecord<CompiledProcedureSummary>> {
        use crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity;
        let records = self.summary_member_records(key, owners);
        let mut counts = actual_counts.to_vec();
        counts.sort_unstable();
        counts.dedup();
        let mut candidates = Vec::new();
        for (count_index, count) in counts.into_iter().enumerate() {
            for (index, record) in records.iter().enumerate() {
                let target = &record.record.target;
                let (owner, _) = authored_procedure_target_identity(&target.path, &target.symbol)
                    .expect("a member summary has an authored owner");
                let owner = owners
                    .iter()
                    .position(|name| name == &owner)
                    .expect("member question restricts owner spellings");
                if !target.variadic && target.parameter_count == count {
                    candidates.push(((count_index, 0, 0, 0, owner, index), record.clone()));
                }
                let minimum = procedure_summary_minimum_actual_count(target);
                if target.variadic && minimum <= count {
                    candidates.push(((count_index, 1, minimum, 0, owner, index), record.clone()));
                }
                if target.formals.iter().any(|formal| formal.optional) {
                    let minimum = u32::try_from(
                        target
                            .formals
                            .iter()
                            .filter(|formal| !formal.optional)
                            .count(),
                    )
                    .expect("validated formal count fits u32");
                    if minimum <= count && target.parameter_count >= count {
                        candidates.push((
                            (
                                count_index,
                                2,
                                minimum,
                                target.parameter_count,
                                owner,
                                index,
                            ),
                            record.clone(),
                        ));
                    }
                }
            }
        }
        candidates.sort_by_key(|(order, _)| *order);
        candidates.into_iter().map(|(_, record)| record).collect()
    }

    pub(super) fn applicable_member_summaries(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
        actual_counts: &[u32],
        accepts: impl Fn(
            &ActiveSemanticModelShard,
            &CompiledProcedureSummary,
        ) -> ProcedureSummaryAcceptance,
    ) -> ProcedureSummaryMatch {
        if self.has_row_backed_shards() {
            let owners = self.summary_owner_spellings(key);
            return resolve_procedure_records(
                self.applicable_summary_records(key, &owners, actual_counts),
                procedure_claims_agree,
                accepts,
            );
        }
        let shapes = self.procedure_shapes_for_member(key.language, key.owner, key.member);
        resolve_applicable_procedure_postings_where_for_counts(
            &self.shards,
            shapes.as_deref(),
            key.has_receiver,
            actual_counts,
            accepts,
        )
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn exact_summary_question(
        &self,
        target: ProcedureSummaryTargetKey<'_>,
        shapes: Option<&ProcedureSummaryShapePostings>,
    ) -> ProcedureSummaryMatch {
        let key = (target.has_receiver, target.parameter_count);
        let mut posting = shapes
            .into_iter()
            .flat_map(|shapes| {
                [shapes.fixed.get(&key), shapes.variadic.get(&key)]
                    .into_iter()
                    .flatten()
                    .flatten()
                    .copied()
            })
            .collect::<Vec<_>>();
        posting.sort_by_key(|address| (address.shard, address.record));
        let mut records = self.merged_question(
            "SUMMARY_TARGET",
            statements::SUMMARY_TARGET,
            (
                target.language,
                target.path,
                target.symbol,
                target.has_receiver,
                target.parameter_count,
            ),
            named_params! { ":realm": semantic_pack_realm(target.language), ":path": target.path,
            ":symbol": target.symbol, ":receiver": target.has_receiver,
            ":formal_arity": target.parameter_count },
            Some(&posting),
            |shard, index| shard.decoded().payload().procedure_summaries()?.get(index),
            record_json,
        );
        records.sort_by_key(|record| record.record.target.variadic);
        resolve_procedure_records(records, procedure_declaration_claims_agree, |_, _| {
            ProcedureSummaryAcceptance::Accept(None)
        })
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn declaration_summary_question(
        &self,
        target: ProcedureSummaryDeclarationKey<'_>,
        symbols: Option<&HashMap<String, ProcedureSummaryShapePostings>>,
    ) -> ProcedureSummaryMatch {
        let mut posting = symbols
            .into_iter()
            .flat_map(|symbols| symbols.values())
            .flat_map(|shapes| shapes.fixed.values().chain(shapes.variadic.values()))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        posting.sort_by_key(|address| (address.shard, address.record));
        posting.dedup_by_key(|address| (address.shard, address.record));
        let records = self.merged_question(
            "SUMMARY_PATH",
            statements::SUMMARY_PATH,
            (target.language, target.path),
            named_params! { ":realm": semantic_pack_realm(target.language), ":path": target.path },
            Some(&posting),
            |shard, index| shard.decoded().payload().procedure_summaries()?.get(index),
            record_json,
        );
        let mut symbols = HashMap::<&str, ProcedureSummaryShapePostings>::default();
        let mut order = Vec::new();
        let mut entries = 0;
        let mut bytes = 0;
        let limits = SemanticModelRuntimeLimits {
            max_index_entries: usize::MAX,
            max_working_bytes: u64::MAX,
            ..SemanticModelRuntimeLimits::default()
        };
        for (index, record) in records.iter().enumerate() {
            let symbol = record.record.target.symbol.as_str();
            if !symbols.contains_key(symbol) {
                order.push(symbol);
            }
            let address = RecordAddress {
                shard: 0,
                record: u32::try_from(index)
                    .expect("validated summary question fits its address space"),
            };
            insert_procedure_posting(
                symbols.entry(symbol).or_default(),
                &record.record.target,
                0,
                address,
                &mut entries,
                &mut bytes,
                limits,
            )
            .expect("query-owned postings fit their result allocation");
        }
        let mut selected = Vec::new();
        for symbol in order {
            if authored_procedure_target_identity(target.path, symbol)
                .is_some_and(|(_, member)| member == target.member)
            {
                for posting in fixed_and_variadic_postings(
                    &symbols[symbol],
                    target.has_receiver,
                    target.parameter_count,
                ) {
                    selected.extend(
                        posting
                            .iter()
                            .map(|address| records[address.record as usize].clone()),
                    );
                }
            }
        }
        resolve_procedure_records(selected, procedure_declaration_claims_agree, |_, _| {
            ProcedureSummaryAcceptance::Accept(None)
        })
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn shard_summary_targets(
        &self,
        shard: &ActiveSemanticModelShard,
        statement_name: &str,
        statement: &str,
    ) -> Vec<Arc<(String, CompiledProcedureTarget)>> {
        let identity = shard
            .row_store
            .expect("row-backed shard has its catalog identity");
        let source = match identity.database {
            CatalogShardDatabase::Durable => "durable",
            CatalogShardDatabase::Session => "session",
        };
        semantic_catalog_question(
            statement_name,
            identity,
            self.source_reader
                .as_ref()
                .expect("row-backed set has its reader")
                .raw_rows(
                    statement,
                    named_params! { ":source_db": source, ":shard_key": identity.shard_key },
                    &self.shards,
                    |row| {
                        let json: String = row.get("target_json")?;
                        let target = serde_json::from_str(&json).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                row.as_ref()
                                    .column_index("target_json")
                                    .expect("summary target column"),
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                        Ok((row.get("record_id")?, target))
                    },
                ),
        )
        .into_iter()
        .map(|row| row.record)
        .collect()
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn refinement_candidate_question(
        &self,
        language: &str,
        member: &str,
        receiver: bool,
        arity: u32,
    ) -> bool {
        let mut posting = Vec::new();
        if let Some(owners) = self
            .indexes
            .procedure_summaries_by_member
            .get(semantic_pack_realm(language))
        {
            for members in owners.values() {
                if let Some(shapes) = members.get(member) {
                    posting.extend(
                        shapes
                            .fixed
                            .values()
                            .chain(shapes.variadic.values())
                            .chain(shapes.optional_fixed.values())
                            .flatten()
                            .copied(),
                    );
                }
            }
        }
        posting.sort_by_key(|a| (a.shard, a.record));
        posting.dedup_by_key(|a| (a.shard, a.record));
        let records = self.merged_question("SUMMARY_MEMBER_CANDIDATES", statements::SUMMARY_MEMBER_CANDIDATES,
            (language,member,receiver), named_params! { ":realm": semantic_pack_realm(language), ":member": member, ":receiver":receiver }, Some(&posting),
            |shard,index| shard.decoded().payload().procedure_summaries()?.get(index), record_json::<CompiledProcedureSummary>);
        let mut owners = HashSet::default();
        for record in records {
            if let Some((owner, _)) = authored_procedure_target_identity(
                &record.record.target.path,
                &record.record.target.symbol,
            ) {
                owners.insert(owner.into_owned());
            }
        }
        owners.into_iter().any(|owner| {
            let key = ProcedureSummaryMemberKey::new(language, &owner, member, receiver, arity);
            resolve_procedure_records(
                self.applicable_summary_records(key, std::slice::from_ref(&owner), &[arity]),
                procedure_claims_agree,
                |_, _| ProcedureSummaryAcceptance::Accept(None),
            )
            .records
            .iter()
            .any(|s| !s.normal_return_type_refinements().is_empty())
        })
    }

    pub(super) fn absence_candidate_question(
        &self,
        language: &str,
    ) -> NormalContinuationAbsenceCandidateIndex {
        let families = semantic_catalog_question(
            "SUMMARY_ABSENT_FAMILIES",
            language,
            self.source_reader
                .as_ref()
                .expect("row-backed set has its reader")
                .scalar_question(
                    statements::SUMMARY_ABSENT_FAMILIES,
                    named_params! { ":realm": semantic_pack_realm(language) },
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, bool>(2)?,
                        ))
                    },
                ),
        );
        let mut postings = ProcedureSummaryTargetPostings::default();
        let mut records = Vec::new();
        let mut entries = 0;
        let mut bytes = 0;
        let limits = SemanticModelRuntimeLimits {
            max_index_entries: usize::MAX,
            max_working_bytes: u64::MAX,
            ..SemanticModelRuntimeLimits::default()
        };
        for (owner, member, receiver) in families {
            let key = ProcedureSummaryMemberKey::new(language, &owner, &member, receiver, 0);
            for record in self.summary_member_records(key, std::slice::from_ref(&owner)) {
                let address = RecordAddress {
                    shard: 0,
                    record: u32::try_from(records.len()).expect("query-owned address space"),
                };
                let shapes = postings
                    .entry(semantic_pack_realm(language).to_owned())
                    .or_default()
                    .entry(owner.clone())
                    .or_default()
                    .entry(member.clone())
                    .or_default();
                insert_procedure_posting(
                    shapes,
                    &record.record.target,
                    0,
                    address,
                    &mut entries,
                    &mut bytes,
                    limits,
                )
                .expect("query-owned postings fit allocation");
                shapes.raw_normal_continuation_absence_claim[usize::from(receiver)] |=
                    record.record.normal_continuation_absent;
                records.push(record);
            }
        }
        build_absence_candidates_with(
            &postings,
            &CancellationToken::new(),
            &mut entries,
            &mut bytes,
            limits,
            &|address| {
                let record = &records[address.record as usize];
                (
                    Arc::clone(&record.record),
                    (record.shard.evidence_rank, record.shard.source_rank),
                )
            },
        )
        .expect("uncancelled query-owned absence candidates fit allocation")
    }
}
