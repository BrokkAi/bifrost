-- Test-only normalized schema-boundary fixture for #11570.
-- Every derived FK descendant is populated, including NO ACTION links.
-- Three unit-summary languages have independent headers and common child rows.
-- Fixed digests are scalar test identities, not authored semantic models.
-- Runtime artifact acquisition is explicitly incomplete; no installed runtime is claimed.
-- $WORKSPACE_ID is replaced by the actual project root identity before execution.
INSERT INTO blobs(id,blob_oid,lang)
VALUES(1,'1111111111111111111111111111111111111111','csharp');

INSERT INTO blobs(id,blob_oid,lang)
VALUES(2,'2222222222222222222222222222222222222222','go');

INSERT INTO blobs(id,blob_oid,lang)
VALUES(3,'3333333333333333333333333333333333333333','java');

INSERT INTO blobs(id,blob_oid,lang)
VALUES(4,'4444444444444444444444444444444444444444','rust');

INSERT INTO blobs(id,blob_oid,lang)
VALUES(5,'5555555555555555555555555555555555555555','python');

INSERT INTO csharp_compilation_sets(set_id,workspace_id,lang,generation,derivation_version,input_digest,output_digest,gaps)
VALUES(1,'$WORKSPACE_ID','csharp',0,1,zeroblob(32),zeroblob(32),jsonb('[]'));

INSERT INTO go_context_selections(selection_id,workspace_id,lang,generation,base_profile_digest,domain_dir,gowork_path,profile_digest,derivation_version)
VALUES(1,'$WORKSPACE_ID','go',0,zeroblob(32),'item','item',zeroblob(32),1);

INSERT INTO jvm_external_provider_publications(provider_id,source_identity,projection_version,projected_rows_sha256,owner_count,member_count,supertype_count)
VALUES('item','item',1,zeroblob(32),1,1,1);

INSERT INTO resolution_identities(id,identity_digest)
VALUES(1,zeroblob(32));

INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,publication_state,output_digest)
VALUES(1,'rust','rust_crate',x'0101010101010101010101010101010101010101010101010101010101010101',x'0101010101010101010101010101010101010101010101010101010101010101','item',1,1,'complete',zeroblob(32));

INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,publication_state,output_digest)
VALUES(2,'go','go_package',x'0202020202020202020202020202020202020202020202020202020202020202',x'0202020202020202020202020202020202020202020202020202020202020202','item',1,1,'complete',zeroblob(32));

INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,publication_state,output_digest)
VALUES(3,'python','python_environment',x'0303030303030303030303030303030303030303030303030303030303030303',x'0303030303030303030303030303030303030303030303030303030303030303','item',1,1,'complete',zeroblob(32));

INSERT INTO rust_crate_reconciliations(workspace_id,generation,revision,derivation_version)
VALUES('$WORKSPACE_ID',0,1,'rust-crate-derivation/legacy');

INSERT INTO rust_crate_topologies(topology_id,topology_digest,crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,publication_state,export_surface_digest)
VALUES(1,zeroblob(32),zeroblob(32),'item','lib','item','2021','std',jsonb('[]'),1,'complete',zeroblob(32));

INSERT INTO workspace_revisions(workspace_id,lang,generation,revision)
VALUES('$WORKSPACE_ID','csharp',0,1);

INSERT INTO workspace_revisions(workspace_id,lang,generation,revision)
VALUES('$WORKSPACE_ID','go',0,1);

INSERT INTO workspace_revisions(workspace_id,lang,generation,revision)
VALUES('$WORKSPACE_ID','java',0,1);

INSERT INTO workspace_revisions(workspace_id,lang,generation,revision)
VALUES('$WORKSPACE_ID','rust',0,1);

INSERT INTO workspace_revisions(workspace_id,lang,generation,revision)
VALUES('$WORKSPACE_ID','python',0,1);

INSERT INTO csharp_compilation_selections(workspace_id,lang,generation,revision,set_id)
VALUES('$WORKSPACE_ID','csharp',0,1,1);

INSERT INTO csharp_compilations(compilation_id,set_id,references_complete,transitive_flow,global_usings_complete,internals_visible_to_complete,global_usings,internals_visible_to)
VALUES(1,1,1,1,1,1,jsonb('[]'),jsonb('[]'));

INSERT INTO go_context_publications(context_id,selection_id,workspace_id,lang,generation,valid_from,input_digest,publication_digest,complete,gaps)
VALUES(1,1,'$WORKSPACE_ID','go',0,1,zeroblob(32),zeroblob(32),1,jsonb('[]'));

INSERT INTO jvm_context_revisions(context_id,workspace_id,lang,generation,revision,derivation_version)
VALUES(1,'$WORKSPACE_ID','java',0,1,1);

INSERT INTO python_runtime_acquisitions(acquisition_id,workspace_id,lang,generation,revision,evidence_digest)
VALUES(1,'$WORKSPACE_ID','python',0,1,zeroblob(32));

INSERT INTO python_unit_summary_roots(summary_id,root_slot,root_path,authority,ordered,observation,target_digest)
VALUES(3,1,'item','workspace',1,'runtime',zeroblob(32));

INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state)
VALUES(1,'csharp','csharp','item',zeroblob(32),1,1,1,'building');

INSERT INTO resolution_unit_summary_consumed_units(summary_id,consumed_unit_key,consumed_output_digest,read_reexport_hop,read_module_hop,read_endpoint,read_absence,read_closure_bindings,read_trait_endpoint,consumed_summary_id)
VALUES(1,zeroblob(32),zeroblob(32),1,1,1,1,1,1,1);

INSERT INTO resolution_unit_summary_consumed_units(summary_id,consumed_unit_key,consumed_output_digest,read_reexport_hop,read_module_hop,read_endpoint,read_absence,read_closure_bindings,read_trait_endpoint,consumed_summary_id)
VALUES(2,zeroblob(32),zeroblob(32),1,1,1,1,1,1,2);

INSERT INTO resolution_unit_summary_consumed_units(summary_id,consumed_unit_key,consumed_output_digest,read_reexport_hop,read_module_hop,read_endpoint,read_absence,read_closure_bindings,read_trait_endpoint,consumed_summary_id)
VALUES(3,zeroblob(32),zeroblob(32),1,1,1,1,1,1,3);

INSERT INTO resolution_unit_summary_containers(summary_id,container_path)
VALUES(1,'');

INSERT INTO resolution_unit_summary_containers(summary_id,container_path)
VALUES(2,'');

INSERT INTO resolution_unit_summary_containers(summary_id,container_path)
VALUES(3,'');

INSERT INTO resolution_unit_summary_dependencies(summary_id,dependency_ordinal,dependency_unit_key,consumed_output_digest,boundary)
VALUES(1,0,zeroblob(32),zeroblob(32),'workspace');

INSERT INTO resolution_unit_summary_dependencies(summary_id,dependency_ordinal,dependency_unit_key,consumed_output_digest,boundary)
VALUES(2,0,zeroblob(32),zeroblob(32),'workspace');

INSERT INTO resolution_unit_summary_dependencies(summary_id,dependency_ordinal,dependency_unit_key,consumed_output_digest,boundary)
VALUES(3,0,zeroblob(32),zeroblob(32),'workspace');

INSERT INTO resolution_unit_summary_dependency_names(summary_id,role,name)
VALUES(1,'item','item');

INSERT INTO resolution_unit_summary_dependency_names(summary_id,role,name)
VALUES(2,'item','item');

INSERT INTO resolution_unit_summary_dependency_names(summary_id,role,name)
VALUES(3,'item','item');

INSERT INTO resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail)
VALUES(1,'item','item',jsonb('[]'));

INSERT INTO resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail)
VALUES(2,'item','item',jsonb('[]'));

INSERT INTO resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail)
VALUES(3,'item','item',jsonb('[]'));

INSERT INTO resolution_unit_summary_input_files(summary_id,input_ordinal,rel_path,source_role)
VALUES(1,0,'item','item');

INSERT INTO resolution_unit_summary_input_files(summary_id,input_ordinal,rel_path,source_role)
VALUES(2,0,'item','item');

INSERT INTO resolution_unit_summary_input_files(summary_id,input_ordinal,rel_path,source_role)
VALUES(3,0,'item','item');

INSERT INTO resolution_unit_summary_members(summary_id,member_ordinal,rel_path,source_role,blob_id)
VALUES(1,0,'item','item',4);

INSERT INTO resolution_unit_summary_members(summary_id,member_ordinal,rel_path,source_role,blob_id)
VALUES(2,0,'item','item',2);

INSERT INTO resolution_unit_summary_members(summary_id,member_ordinal,rel_path,source_role,blob_id)
VALUES(3,0,'item','item',5);

INSERT INTO resolution_unit_summary_reads(summary_id,read_ordinal,kind,key_digest,digest)
VALUES(1,0,'epoch',zeroblob(32),zeroblob(32));

INSERT INTO resolution_unit_summary_reads(summary_id,read_ordinal,kind,key_digest,digest)
VALUES(2,0,'epoch',zeroblob(32),zeroblob(32));

INSERT INTO resolution_unit_summary_reads(summary_id,read_ordinal,kind,key_digest,digest)
VALUES(3,0,'epoch',zeroblob(32),zeroblob(32));

INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id)
VALUES('$WORKSPACE_ID','rust',0,x'0101010101010101010101010101010101010101010101010101010101010101',1,1);

INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id)
VALUES('$WORKSPACE_ID','go',0,x'0202020202020202020202020202020202020202020202020202020202020202',1,2);

INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id)
VALUES('$WORKSPACE_ID','python',0,x'0303030303030303030303030303030303030303030303030303030303030303',1,3);

INSERT INTO rust_resolution_unit_summary_contexts(summary_id,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,development_capable)
VALUES(1,'lib','item','2021','std',jsonb('[]'),1,1);

INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail)
VALUES(1,'item','item',jsonb('{}'));

INSERT INTO rust_resolution_unit_summary_public_surface_gaps(summary_id,gap_kind,subject)
VALUES(1,'external_dependency','public-module-surface:crate');

INSERT INTO rust_source_listing_certificates(workspace_id,lang,generation,revision,derivation_version,complete)
VALUES('$WORKSPACE_ID','rust',0,1,1,1);

INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,valid_from,projection_digest)
VALUES(1,'$WORKSPACE_ID','csharp',0,'Program.cs','1111111111111111111111111111111111111111',1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,valid_from,projection_digest)
VALUES(2,'$WORKSPACE_ID','go',0,'main.go','2222222222222222222222222222222222222222',1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,valid_from,projection_digest)
VALUES(3,'$WORKSPACE_ID','java',0,'Main.java','3333333333333333333333333333333333333333',1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,valid_from,projection_digest)
VALUES(4,'$WORKSPACE_ID','rust',0,'src/lib.rs','4444444444444444444444444444444444444444',1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,valid_from,projection_digest)
VALUES(5,'$WORKSPACE_ID','python',0,'module.py','5555555555555555555555555555555555555555',1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

INSERT INTO csharp_compilation_items(compilation_id,ordinal,set_id,kind,rel_path)
VALUES(1,0,1,'include','item');

INSERT INTO csharp_compilation_members(workspace_id,generation,compilation_id,rel_path,file_version_id,valid_from,lang)
VALUES('$WORKSPACE_ID',0,1,'item',1,1,'csharp');

INSERT INTO csharp_compilation_symbols(compilation_id,symbol,source)
VALUES(1,'item','sdk');

INSERT INTO csharp_compilation_using_coverage(workspace_id,generation,compilation_id,valid_from,membership_complete,publications_expected,publications_installed,metadata_complete,reasons,lang)
VALUES('$WORKSPACE_ID',0,1,1,1,1,1,1,jsonb('[]'),'csharp');

INSERT INTO csharp_project_references(from_compilation_id,target_compilation_id)
VALUES(1,1);

INSERT INTO go_context_domain_modules(context_id,module_dir,module_path)
VALUES(1,'item','item');

INSERT INTO go_package_instances(package_id,context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key)
VALUES(1,1,'example.test/upgrade','upgrade','','.',zeroblob(32),1,jsonb('[]'),x'0202020202020202020202020202020202020202020202020202020202020202');

INSERT INTO jvm_projects(project_id,context_id,pom_file_version_id,directory,group_id,artifact_id,version_state)
VALUES(1,1,3,'item','item','item','missing');

INSERT INTO python_runtime_environments(environment_id,acquisition_id,source_scope,status,scope_path,scope_depth)
VALUES(1,1,'.','incomplete','.',0);

INSERT INTO python_unit_summary_imports(summary_id,member_ordinal,importer_container,target_container,module_name,relative_level,requested_name,bound_name,form,state,import_surface_ordinal)
VALUES(3,0,'','','item',1,'item','item','module','activation_open',0);

INSERT INTO python_unit_summary_providers(summary_id,container_path,module_name,parent_module,root_slot,kind,state,rel_path,provider_digest,member_ordinal)
VALUES(3,'','item','item',1,'module','selected','item',zeroblob(32),0);

INSERT INTO resolution_root_imports(blob_id,import_site,root_scope,anchor,kind)
VALUES(1,1,0,'lexical','named');

INSERT INTO resolution_unit_summary_exports(summary_id,identity_id,namespace,visibility,origin,target_kind,export_rank,alias_dependency_ordinal,alias_identity_id,declaration_member_ordinal,site_surface_ordinal,declaration_surface_ordinal)
VALUES(1,1,'type','exported','alias','foreign',0,0,1,NULL,NULL,NULL);

INSERT INTO resolution_unit_summary_exports(summary_id,identity_id,namespace,visibility,origin,target_kind,export_rank,alias_dependency_ordinal,alias_identity_id,declaration_member_ordinal,site_surface_ordinal,declaration_surface_ordinal)
VALUES(2,1,'type','exported','alias','foreign',0,0,1,NULL,NULL,NULL);

INSERT INTO resolution_unit_summary_exports(summary_id,identity_id,namespace,visibility,origin,target_kind,export_rank,alias_dependency_ordinal,alias_identity_id,declaration_member_ordinal,site_surface_ordinal,declaration_surface_ordinal)
VALUES(3,1,'type','exported','alias','foreign',0,0,1,NULL,NULL,NULL);

INSERT INTO resolution_unit_summary_imports(summary_id,member_ordinal,import_surface_ordinal,kind,state,dependency_ordinal,site_surface_ordinal)
VALUES(1,0,0,'named','resolved',0,0);

INSERT INTO resolution_unit_summary_imports(summary_id,member_ordinal,import_surface_ordinal,kind,state,dependency_ordinal,site_surface_ordinal)
VALUES(2,0,0,'named','resolved',0,0);

INSERT INTO resolution_unit_summary_imports(summary_id,member_ordinal,import_surface_ordinal,kind,state,dependency_ordinal,site_surface_ordinal)
VALUES(3,0,0,'named','resolved',0,0);

INSERT INTO resolution_unit_summary_placements(summary_id,container_path,member_ordinal)
VALUES(1,'',0);

INSERT INTO resolution_unit_summary_placements(summary_id,container_path,member_ordinal)
VALUES(2,'',0);

INSERT INTO resolution_unit_summary_placements(summary_id,container_path,member_ordinal)
VALUES(3,'',0);

INSERT INTO rust_resolution_unit_summary_binding_completeness(summary_id,member_ordinal,complete,gap_kind,gap_subject)
VALUES(1,0,1,'complete','');

INSERT INTO rust_resolution_unit_summary_binding_owners(summary_id,owner_handle,module_path,kind,closed,member_ordinal)
VALUES(1,1,'','module',1,NULL);

INSERT INTO rust_resolution_unit_summary_container_attributes(summary_id,container_path,kind)
VALUES(1,'','module');

INSERT INTO rust_resolution_unit_summary_effective_bindings(summary_id,member_ordinal,module_path,binder_scope,name,namespace,visibility_kind,target_unit_key,target_module_path,target_name,route_provenance_ordinal,target_identity_id)
VALUES(1,0,'item',0,'item','type','public',zeroblob(32),'item','item',0,1);

INSERT INTO rust_resolution_unit_summary_file_naming(summary_id,member_ordinal,package_components,package_path,root_components)
VALUES(1,0,jsonb('[]'),'item',jsonb('[]'));

INSERT INTO rust_resolution_unit_summary_import_route_provenance(summary_id,member_ordinal,import_id,import_ordinal,route_provenance_ordinal,hop_ordinal,target_unit_key,target_binding_module_path,target_binding_name,namespace,target_identity_id)
VALUES(1,0,1,0,0,0,zeroblob(32),'item','item','type',1);

INSERT INTO rust_resolution_unit_summary_inactive_placements(summary_id,placement_ordinal,module_path,input_file_ordinal,placement,activation)
VALUES(1,0,'',0,'cfg-inactive',0);

INSERT INTO rust_resolution_unit_summary_inherent_impls(summary_id,impl_member_ordinal,impl_site,impl_declaration_id,subject_ordinal,subject_form,subject_member_ordinal,subject_site)
VALUES(1,0,1,1,0,'local_site',0,1);

INSERT INTO rust_resolution_unit_summary_macro_decisions(summary_id,member_ordinal,invocation_occurrence_id,decoration_cfg)
VALUES(1,0,1,'item');

INSERT INTO rust_resolution_unit_summary_unresolved_inherent_impls(summary_id,impl_member_ordinal,impl_site,reason)
VALUES(1,0,1,'unbound');

INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id,profile_digest,manifest_file_version_id)
VALUES('$WORKSPACE_ID','rust',0,x'0101010101010101010101010101010101010101010101010101010101010101',1,1,1,zeroblob(32),4);

INSERT INTO rust_source_listing_failures(workspace_id,lang,generation,revision,rel_path,reason)
VALUES('$WORKSPACE_ID','rust',0,1,'item','item');

INSERT INTO csharp_global_using_extent(workspace_id,generation,compilation_id,rel_path,blob_id,import_site,valid_from,lang)
VALUES('$WORKSPACE_ID',0,1,'item',1,1,1,'csharp');

INSERT INTO go_package_files(package_id,source_role,rel_path)
VALUES(1,'go','item');

INSERT INTO go_package_imports(import_id,context_id,importer_package_id,source_spelling,import_role,complete,gaps,target_package_id)
VALUES(1,1,1,'item','go',1,jsonb('[]'),1);

INSERT INTO jvm_context_gaps(gap_id,context_id,code,evidence,project_id,input_file_version_id)
VALUES(1,1,'item','item',1,3);

INSERT INTO jvm_direct_dependencies(context_id,project_id,ordinal,group_id_state,artifact_id_state,version_state,artifact_type_state,classifier_state,scope_state,optional_state)
VALUES(1,1,0,'missing','missing','missing','missing','missing','missing','missing');

INSERT INTO jvm_source_roots(root_id,context_id,project_id,role,root_path)
VALUES(1,1,1,'main','item');

INSERT INTO python_runtime_artifacts(artifact_id,environment_id,acquisition_id,archive_path,installed_root,status)
VALUES(1,1,1,'archive.whl','site-packages','incomplete');

INSERT INTO python_runtime_declared_environments(declared_environment_id,environment_id,acquisition_id,producer_version,resolver_version,interpreter_path,interpreter_sha256,interpreter_implementation,interpreter_python_version,interpreter_abi,interpreter_platform,isolation_mode,site_startup_mode,environment_mode,import_path_mode,finder_mode,editable_installs_mode,native_extensions_mode,entry_mode,entry_root_slot_id,entry_relative_path,working_directory_root_slot_id,working_directory,project_config_algorithm,project_config_coverage,project_config_canonicalization,project_config_digest)
VALUES(1,1,1,'fixture-0405','fixture-0405','python','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','cpython','3.12','cp312','posix','isolated','disabled','cleared','declared_roots_only','standard_filesystem','disabled','disabled','script','item','item','item','item','sha-256','resolver-affecting-config','https://bifrost.brokk.ai/csmi/python/project-config/rfc8785-v1','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

INSERT INTO python_unit_summary_spellings(summary_id,module_name,source_root,target_container,admitted)
VALUES(3,'item','item','',1);

INSERT INTO python_unit_summary_surfaces(summary_id,container_path,surface,policy)
VALUES(3,'','module','slots');

INSERT INTO rust_resolution_unit_summary_binding_blockers(summary_id,owner_handle,namespace,name,reason,boundary,evidence_unit_key,evidence_module_path,evidence_kind,blocker_ordinal,evidence_form,evidence_owner_handle,evidence_member_ordinal,evidence_declaration_id)
VALUES(1,1,'type','item','item','item',zeroblob(32),'item','declaration',0,'local',NULL,0,1);

INSERT INTO rust_resolution_unit_summary_binding_names(summary_id,owner_handle,namespace,name,complete)
VALUES(1,1,'type','item',1);

INSERT INTO rust_resolution_unit_summary_exports(summary_id,module_path,namespace,name,identity_id,visibility,origin,alias_dependency_ordinal,declaration_member_ordinal,alias_identity_id,declaration_site)
VALUES(1,'crate','type','item',1,'public','declaration',NULL,0,NULL,1);

INSERT INTO rust_resolution_unit_summary_generated_names(summary_id,module_path,member_ordinal,invocation_occurrence_id,declaration_id,namespace,name,visibility,module_item)
VALUES(1,'crate',0,1,1,'type','item','public',1);

INSERT INTO rust_resolution_unit_summary_glob_imports(summary_id,member_ordinal,source_import_id,route_ordinal,module_path,binder_scope,target_unit_key,target_module_path,dependency_ordinal)
VALUES(1,0,1,0,'crate',0,zeroblob(32),'item',0);

INSERT INTO rust_resolution_unit_summary_glob_reexport_routes(summary_id,module_path,target_unit_key,target_module_path,visibility,dependency_ordinal)
VALUES(1,'crate',zeroblob(32),'item','public',0);

INSERT INTO rust_resolution_unit_summary_import_routes(summary_id,member_ordinal,import_id,route_ordinal,module_path,binder_scope,namespace,bound_name,target_unit_key,target_module_path,target_name,dependency_ordinal)
VALUES(1,0,1,0,'crate',0,'type','item',zeroblob(32),'item','item',0);

INSERT INTO rust_resolution_unit_summary_placement_attributes(summary_id,container_path,member_ordinal,placement,source_kind)
VALUES(1,'',0,'root','declared');

INSERT INTO rust_resolution_unit_summary_reexport_routes(summary_id,module_path,bound_name,target_unit_key,target_module_path,target_name,visibility,dependency_ordinal)
VALUES(1,'crate','item',zeroblob(32),'item','item','public',0);

INSERT INTO jvm_source_root_files(context_id,root_id,source_file_version_id)
VALUES(1,1,3);

INSERT INTO python_unit_summary_export_names(summary_id,container_path,surface,name)
VALUES(3,'','module','item');

INSERT INTO rust_resolution_unit_summary_binding_alternatives(summary_id,alternative_handle,owner_handle,namespace,name,target_unit_key,target_module_path,target_name,origin,target_form,visibility,provider_form,provider_member_ordinal,target_member_ordinal,target_site)
VALUES(1,1,1,'type','item',zeroblob(32),'item','item','declaration','local_site','public','none',NULL,0,1);

INSERT INTO rust_resolution_unit_summary_root_routes(root_route_id,summary_id,member_ordinal,module_path,route_key,reference_source_site,target_unit_key,target_module_path,target_name)
VALUES(1,1,0,'crate',1,1,zeroblob(32),'crate','item');

INSERT INTO rust_resolution_unit_summary_trait_endpoints(summary_id,member_ordinal,owner_module_path,source_relation_key,endpoint_role,endpoint_state,impl_site,dependency_ordinal,local_target_member_ordinal,target_identity_id,target_unit_key,target_module_path)
VALUES(1,0,'crate',1,'subject','resolved',1,0,0,1,x'0101010101010101010101010101010101010101010101010101010101010101','crate');

-- Current heads make first use reconcile the preserved revision, not an empty workspace.
INSERT INTO workspace_heads(workspace_id,lang,generation,revision)
SELECT workspace_id,lang,generation,revision FROM workspace_revisions;
