use super::*;

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#4644: static and class receivers collapsed in method policy evidence"
)]
fn callable_signature_rows_preserve_python_receiver_kind_and_source_evidence() {
    let source = concat!(
        "class Factory:\n",
        "    @staticmethod\n",
        "    def static(value):\n",
        "        return value\n",
        "    @classmethod\n",
        "    def wrong_classmethod(wrong):\n",
        "        return wrong\n",
        "    @classmethod\n",
        "    def empty_classmethod():\n",
        "        return 1\n",
        "    def instance(wrong):\n",
        "        return wrong\n",
        "    def static_assigned(wrong):\n",
        "        return wrong\n",
        "    static_assigned = staticmethod(static_assigned)\n",
        "    def class_assigned(wrong):\n",
        "        return wrong\n",
        "    class_assigned = classmethod(class_assigned)\n",
        "class Meta(type):\n",
        "    def meta_receiver(wrong):\n",
        "        return wrong\n",
        "class Helpers:\n",
        "    def helper(value):\n",
        "        return value\n",
        "    helper(1)\n",
        "    @helper()\n",
        "    def decorated(self):\n",
        "        return self\n",
        "import zope.interface\n",
        "class ZopeRoot(zope.interface.Interface):\n",
        "    def interface_method(argument):\n",
        "        return argument\n",
        "class ObjectRoot(object):\n",
        "    def object_method(argument):\n",
        "        return argument\n",
    );
    let (_project, workspace) = inline_project::python_workspace(&[("src/main.py", source)]);
    let query =
        CodeQuery::from_source("(callable-signature (enclosing-decl (language python (method))))")
            .expect("callable-signature query");
    let detailed = execute_code_query_detailed(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        detailed.result.results.len(),
        11,
        "{}",
        detailed.result.render_text()
    );

    let mut by_name = std::collections::HashMap::new();
    for (index, item) in detailed.result.results.iter().enumerate() {
        let CodeQueryResultValue::CallableSignature { value } = &item.value else {
            panic!("callable-signature returns signature rows");
        };
        let name = value
            .declaration
            .fq_name
            .rsplit('.')
            .next()
            .expect("method name");
        assert!(by_name.insert(name.to_owned(), (index, value)).is_none());
        let evidence = &detailed.evidence[index];
        assert_eq!(evidence.domain, DetailedCodeQueryDomain::CallableSignature);
        let byte_span = evidence.byte_span.as_ref().expect("method source span");
        assert_eq!(
            evidence.source_slice_sha256,
            Some(Sha256::digest(&source.as_bytes()[byte_span.clone()]).into())
        );
    }

    let (_, static_method) = by_name.get("static").expect("static method");
    assert_eq!(static_method.python_method_kind, Some("static"));
    assert_eq!(static_method.python_owner_is_metaclass, Some(false));

    let (_, class_method) = by_name.get("wrong_classmethod").expect("class method");
    assert_eq!(class_method.python_method_kind, Some("class"));
    assert_eq!(class_method.first_parameter.as_deref(), Some("wrong"));

    let (_, empty_class_method) = by_name
        .get("empty_classmethod")
        .expect("zero-parameter class method");
    assert_eq!(empty_class_method.python_method_kind, Some("class"));
    assert_eq!(empty_class_method.parameter_count, 0);

    let (_, instance_method) = by_name.get("instance").expect("instance method");
    assert_eq!(instance_method.python_method_kind, Some("instance"));

    let (_, assigned_static_method) = by_name
        .get("static_assigned")
        .expect("assigned static method");
    assert_eq!(assigned_static_method.python_method_kind, Some("static"));

    let (_, assigned_class_method) = by_name
        .get("class_assigned")
        .expect("assigned class method");
    assert_eq!(assigned_class_method.python_method_kind, Some("class"));

    let (_, metaclass_method) = by_name.get("meta_receiver").expect("metaclass method");
    assert_eq!(metaclass_method.python_method_kind, Some("instance"));
    assert_eq!(metaclass_method.python_owner_is_metaclass, Some(true));

    let (_, helper_method) = by_name.get("helper").expect("class-body helper");
    assert_eq!(helper_method.python_used_in_class_body, Some(true));

    let (_, interface_method) = by_name
        .get("interface_method")
        .expect("method on an imported Zope interface");
    assert_eq!(interface_method.python_owner_is_metaclass, Some(false));
    assert_eq!(interface_method.python_owner_is_zope_interface, Some(true));

    let (_, object_method) = by_name
        .get("object_method")
        .expect("method on an explicit object subclass");
    assert_eq!(object_method.python_owner_is_metaclass, Some(false));
    assert_eq!(object_method.python_owner_is_zope_interface, Some(false));
}
