//! Query-local merge of decoded postings and catalog rows in publication order.

use super::*;
use crate::analyzer::store::model_catalog::{OwnedCatalogRow, semantic_catalog_question};
use rusqlite::named_params;

pub fn shard_record_order_key(
    shard: &ActiveSemanticModelShard,
    record_key: i64,
) -> (&str, &str, &str, Option<u8>, Option<i64>, i64) {
    (
        &shard.manifest.pack_id,
        &shard.descriptor.shard_id,
        &shard.manifest.semantic_sha256,
        shard.row_store.map(|identity| match identity.database {
            super::CatalogShardDatabase::Durable => 0,
            super::CatalogShardDatabase::Session => 1,
        }),
        shard.row_store.map(|identity| identity.shard_key),
        record_key,
    )
}

pub(super) fn record_json<T: serde::de::DeserializeOwned>(
    row: &OwnedCatalogRow<'_>,
) -> rusqlite::Result<T> {
    let json: String = row.get("record_json")?;
    serde_json::from_str(&json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            row.column_index("record_json").expect("record JSON column"),
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
        owners: RowOwners,
        key: impl std::fmt::Debug,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        posting: Option<&Vec<RecordAddress>>,
        decoded: impl Fn(&ActiveSemanticModelShard, usize) -> Option<&Arc<T>>,
        decode: impl Fn(&OwnedCatalogRow<'_>) -> rusqlite::Result<T>,
    ) -> FamilyRows<Vec<ActivatedSemanticModelRecord<T>>> {
        let mut fetched = Vec::new();
        let mut jvm_open = owners.jvm_open;
        for reader in &owners.readers {
            match semantic_catalog_question(
                statement_name,
                &key,
                (reader.as_ref() as &dyn CatalogRowReader).raw_rows(
                    statement,
                    bindings,
                    &self.shards,
                    |row| Ok((row.get::<_, i64>("record_key")?, Arc::new(decode(row)?))),
                ),
            ) {
                Ok(rows) => fetched.extend(rows),
                Err(open) => {
                    let previous = jvm_open.get_or_insert(open);
                    *previous = previous.merge(open);
                }
            }
        }
        let rows = fetched;
        let mut rows = rows
            .into_iter()
            .filter_map(|row| {
                let shard = self
                    .shards
                    .iter()
                    .find(|s| Arc::ptr_eq(&s.metadata, &row.shard))
                    .expect("active row metadata belongs to this publication");
                shard.decoded.is_none().then(|| {
                    (
                        shard_record_order_key(shard, row.record.0),
                        ActivatedSemanticModelRecord {
                            shard: Arc::clone(shard),
                            record: Arc::clone(&row.record.1),
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows.dedup_by(|a, b| a.0 == b.0);
        let decoded = posting.into_iter().flatten().map(|address| {
            let shard = &self.shards[address.shard as usize];
            debug_assert!(
                shard.decoded.is_some(),
                "only decoded shards have matcher postings"
            );
            (
                shard_record_order_key(shard, i64::from(address.record)),
                ActivatedSemanticModelRecord {
                    record: Arc::clone(
                        decoded(shard, address.record as usize)
                            .expect("decoded posting addresses its record"),
                    ),
                    shard: Arc::clone(shard),
                },
            )
        });
        let mut decoded = decoded.collect::<Vec<_>>();
        decoded.sort_by(|a, b| a.0.cmp(&b.0));
        FamilyRows {
            rows: merge_ordered_semantic_results(decoded, rows, |a, b| a.0.cmp(&b.0))
                .into_iter()
                .map(|(_, record)| record)
                .collect(),
            jvm_open,
        }
    }

    pub(super) fn type_question(
        &self,
        owners: RowOwners,
        statement_name: &str,
        statement: &str,
        key: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        posting: Option<&Vec<RecordAddress>>,
    ) -> FamilyRows<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        self.merged_question(
            statement_name,
            statement,
            owners,
            key,
            bindings,
            posting,
            |shard, index| shard.decoded().payload().declaration_facts()?.0.get(index),
            record_json,
        )
        .map(|rows| {
            rows.into_iter()
                .filter(|r| !r.shard.guard_excludes(r.record.guard.as_ref()))
                .collect()
        })
    }

    pub(super) fn member_question(
        &self,
        owners: RowOwners,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        posting: Option<&Vec<RecordAddress>>,
    ) -> FamilyRows<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        self.merged_question(
            statement_name,
            statement,
            owners,
            key,
            bindings,
            posting,
            |shard, index| shard.decoded().payload().declaration_facts()?.1.get(index),
            record_json,
        )
        .map(|rows| {
            rows.into_iter()
                .filter(|r| !r.shard.guard_excludes(r.record.guard.as_ref()))
                .collect()
        })
    }

    pub(super) fn relation_question(
        &self,
        owners: RowOwners,
        statement_name: &str,
        statement: &str,
        id: &str,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<RelationFact> {
        resolve_records(self.merged_question(
            statement_name,
            statement,
            owners,
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
                            row.column_index("relation_kind")
                                .expect("relation kind column"),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                })
            },
        ))
    }

    /// Generator rules live only in generator-rule shards, which the activation
    /// always owns (`request_owned` excludes their payload kind). So the
    /// activation reader alone answers every rule question, at overlay build
    /// and at request time, and an open JVM request owner never makes a rule
    /// lookup open.
    pub(super) fn rule_question(
        &self,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<GeneratorRule> {
        self.rule_question_for_realm(None, statement_name, statement, key, bindings, posting)
    }

    pub(super) fn rule_question_for_realm(
        &self,
        realm: Option<&str>,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<GeneratorRule> {
        resolve_records(
            self.merged_question(
                statement_name,
                statement,
                self.activation_row_owners(),
                key,
                bindings,
                posting,
                |shard, index| shard.decoded().payload().generator_rules()?.get(index),
                record_json,
            )
            .map(|records| {
                records
                    .into_iter()
                    .filter(|record| {
                        realm.is_none_or(|realm| {
                            semantic_pack_realm(&record.shard.manifest.language) == realm
                        })
                    })
                    .collect()
            }),
        )
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
    ) -> Result<Vec<Arc<T>>, FamilyOpen> {
        let identity = shard
            .row_store
            .expect("row-backed shard has its catalog identity");
        let source = match identity.database {
            CatalogShardDatabase::Durable => "durable",
            CatalogShardDatabase::Session => "session",
        };
        Ok(semantic_catalog_question(
            statement_name,
            identity,
            (self.shard_row_reader(shard)?.as_ref() as &dyn CatalogRowReader).raw_records(
                statement,
                named_params! { ":source_db": source, ":shard_key": identity.shard_key },
                &self.shards,
            ),
        )?
        .into_iter()
        .map(|record| record.record)
        .collect())
    }

    pub(super) fn shard_payload<T: serde::de::DeserializeOwned>(
        &self,
        shard: &ActiveSemanticModelShard,
        statement_name: &str,
        statement: &str,
    ) -> Result<Option<Arc<T>>, FamilyOpen> {
        let mut records = self.shard_records(shard, statement_name, statement)?;
        debug_assert!(records.len() <= 1, "one whole-payload row per shard");
        Ok(records.pop())
    }

    pub(super) fn has_family(
        &self,
        shard: &ActiveSemanticModelShard,
        family: brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily,
    ) -> Result<bool, FamilyOpen> {
        let identity = shard
            .row_store
            .expect("row-backed shard has its catalog identity");
        semantic_catalog_question(
            "PAYLOAD_FAMILY_PRESENCE",
            (identity, family),
            (self.shard_row_reader(shard)?.as_ref() as &dyn CatalogRowReader)
                .payload_family_presence(identity, family),
        )
    }
}

impl ResolvedActiveSemanticModels {
    /// Open when the owner's spellings may be missing, so that no summary
    /// question is narrowed to a partial spelling set.
    pub(super) fn summary_owner_spellings(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> Result<Vec<String>, FamilyOpen> {
        let realm = semantic_pack_realm(key.language);
        let mut names = HashSet::default();
        let declarations = self.all_type_records_named(key.owner);
        if let Some(open) = declarations.open_for_language(key.language) {
            return Err(open);
        }
        for declaration in declarations.rows {
            if declaration.shard.extraction().is_some()
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
        Ok(names)
    }

    pub(super) fn summary_member_records(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
        owners: &[String],
    ) -> FamilyRows<Vec<ActivatedSemanticModelRecord<CompiledProcedureSummary>>> {
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
            self.question_row_owners(Some(realm)),             (key.language, owners, key.member, key.has_receiver),
            named_params! { ":realm": realm, ":owners": serde_json::to_string(owners).expect("owner spellings serialize"),
                ":member": key.member, ":receiver": key.has_receiver }, Some(&posting),
            |shard, index| shard.decoded().payload().procedure_summaries()?.get(index), record_json)
            .map(|rows| rows.into_iter().filter(|r| r.record.target.has_receiver == key.has_receiver).collect())
    }

    pub(super) fn applicable_summary_records(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
        owners: &[String],
        actual_counts: &[u32],
    ) -> FamilyRows<Vec<ActivatedSemanticModelRecord<CompiledProcedureSummary>>> {
        use crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity;
        let FamilyRows {
            rows: records,
            jvm_open,
        } = self.summary_member_records(key, owners);
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
        FamilyRows {
            rows: candidates.into_iter().map(|(_, record)| record).collect(),
            jvm_open,
        }
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
            let candidates = match self.summary_owner_spellings(key) {
                Ok(owners) => self.applicable_summary_records(key, &owners, actual_counts),
                Err(open) => FamilyRows {
                    rows: Vec::new(),
                    jvm_open: Some(open),
                },
            };
            return resolve_procedure_records(candidates, procedure_claims_agree, accepts);
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
            self.question_row_owners(Some(semantic_pack_realm(target.language))),
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
        records
            .rows
            .sort_by_key(|record| record.record.target.variadic);
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
        let FamilyRows {
            rows: records,
            jvm_open,
        } = self.merged_question(
            "SUMMARY_PATH",
            statements::SUMMARY_PATH,
            self.question_row_owners(Some(semantic_pack_realm(target.language))),
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
        resolve_procedure_records(
            FamilyRows {
                rows: selected,
                jvm_open,
            },
            procedure_declaration_claims_agree,
            |_, _| ProcedureSummaryAcceptance::Accept(None),
        )
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn shard_summary_targets(
        &self,
        shard: &ActiveSemanticModelShard,
        statement_name: &str,
        statement: &str,
    ) -> Result<Vec<Arc<(String, CompiledProcedureTarget)>>, FamilyOpen> {
        let identity = shard
            .row_store
            .expect("row-backed shard has its catalog identity");
        let source = match identity.database {
            CatalogShardDatabase::Durable => "durable",
            CatalogShardDatabase::Session => "session",
        };
        Ok(semantic_catalog_question(
            statement_name,
            identity,
            (self.shard_row_reader(shard)?.as_ref() as &dyn CatalogRowReader).raw_rows(
                statement,
                named_params! { ":source_db": source, ":shard_key": identity.shard_key },
                &self.shards,
                |row| {
                    let json: String = row.get("target_json")?;
                    let target = serde_json::from_str(&json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            row.column_index("target_json")
                                .expect("summary target column"),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok((row.get("record_id")?, target))
                },
            ),
        )?
        .into_iter()
        .map(|row| row.record)
        .collect())
    }
}

impl ResolvedActiveSemanticModels {
    pub(super) fn refinement_candidate_question(
        &self,
        language: &str,
        member: &str,
        receiver: bool,
        arity: u32,
    ) -> FamilyPresence {
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
        let FamilyRows { rows: records, jvm_open } = self.merged_question("SUMMARY_MEMBER_CANDIDATES", statements::SUMMARY_MEMBER_CANDIDATES,
            self.question_row_owners(Some(semantic_pack_realm(language))),             (language,member,receiver), named_params! { ":realm": semantic_pack_realm(language), ":member": member, ":receiver":receiver }, Some(&posting),
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
        let mut open = jvm_open;
        for owner in owners {
            let key = ProcedureSummaryMemberKey::new(language, &owner, member, receiver, arity);
            let matched = resolve_procedure_records(
                self.applicable_summary_records(key, std::slice::from_ref(&owner), &[arity]),
                procedure_claims_agree,
                |_, _| ProcedureSummaryAcceptance::Accept(None),
            );
            if matched
                .records
                .iter()
                .any(|s| !s.normal_return_type_refinements().is_empty())
            {
                return FamilyPresence::Present;
            }
            if let SemanticModelMatchDisposition::Open(owner_open) = matched.disposition {
                open = Some(open.map_or(owner_open, |previous: FamilyOpen| {
                    previous.merge(owner_open)
                }));
            }
        }
        open.map_or(FamilyPresence::Absent, FamilyPresence::Open)
    }

    pub(super) fn absence_candidate_question(
        &self,
        language: &str,
    ) -> Result<NormalContinuationAbsenceCandidateIndex, FamilyOpen> {
        let mut families = Vec::new();
        let owners = self.question_row_owners(Some(semantic_pack_realm(language)));
        // A partial family list would read as "no absence candidates".
        if let Some(open) = owners.jvm_open {
            return Err(open);
        }
        for reader in owners.readers {
            families.extend(semantic_catalog_question(
                "SUMMARY_ABSENT_FAMILIES",
                language,
                (reader.as_ref() as &dyn CatalogRowReader).scalar_question(
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
            )?);
        }
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
            let records_for_owner = self.summary_member_records(key, std::slice::from_ref(&owner));
            if let Some(open) = records_for_owner.jvm_open {
                return Err(open);
            }
            for record in records_for_owner.rows {
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
        Ok(build_absence_candidates_with(
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
        .expect("uncancelled query-owned absence candidates fit allocation"))
    }
}
