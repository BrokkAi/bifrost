pub use brokk_bifrost_python::exception_identity::{
    python_builtin_exception_is_subclass, python_builtin_exception_name,
};

#[cfg(test)]
mod tests {

    use crate::analyzer::python::exception_identity::python_builtin_exception_is_subclass;

    #[test]
    fn exception_group_inherits_both_exception_families() {
        assert_eq!(
            python_builtin_exception_is_subclass("ExceptionGroup", "Exception"),
            Some(true)
        );
        assert_eq!(
            python_builtin_exception_is_subclass("ExceptionGroup", "BaseException"),
            Some(true)
        );
        assert_eq!(
            python_builtin_exception_is_subclass("ExceptionGroup", "LookupError"),
            Some(false)
        );
        assert_eq!(
            python_builtin_exception_is_subclass("OSError", "IOError"),
            Some(true)
        );
    }
}
