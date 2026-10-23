//! Python language-defined builtin names and the closed object member surface.
//!
//! Audited Python 3.0 through 3.15. Unknown/out-of-range versions do not select
//! version-dependent names. Identity is independent of availability and version.
//! Sources: https://docs.python.org/3.15/library/functions.html,
//! https://docs.python.org/3.15/library/exceptions.html and
//! https://docs.python.org/3.15/reference/datamodel.html.
//! Site-installed conveniences and platform-only names are not language rules.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PythonVersion {
    pub major: u16,
    pub minor: u16,
}
impl PythonVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}
const FIRST: PythonVersion = PythonVersion::new(3, 0);
const END: PythonVersion = PythonVersion::new(3, 16);
// Undeclared projects use 3.9: CPython 3.8 and older were end of life by 2024,
// and large projects such as PyTorch still declare 3.9.
const UNDECLARED_FLOOR: PythonVersion = PythonVersion::new(3, 9);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Present,
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub struct VersionRange {
    pub since: PythonVersion,
}
impl VersionRange {
    pub fn availability(self, version: Option<PythonVersion>) -> Availability {
        let minimum = version.unwrap_or(UNDECLARED_FLOOR);
        if !(FIRST..END).contains(&minimum) || self.since > minimum {
            Availability::Unknown
        } else {
            Availability::Present
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BuiltinKind {
    Type,
    Callable,
    Value,
}
#[derive(Clone, Copy, Debug)]
pub struct Builtin {
    pub name: &'static str,
    pub qualified_name: &'static str,
    pub kind: BuiltinKind,
    pub versions: VersionRange,
}
macro_rules! builtin {
    ($name:ident, $kind:ident, $minor:literal) => {
        Builtin {
            name: stringify!($name),
            qualified_name: concat!("builtins.", stringify!($name)),
            kind: BuiltinKind::$kind,
            versions: VersionRange {
                since: PythonVersion::new(3, $minor),
            },
        }
    };
}

pub const BUILTINS: &[Builtin] = &[
    builtin!(ArithmeticError, Type, 0),
    builtin!(AssertionError, Type, 0),
    builtin!(AttributeError, Type, 0),
    builtin!(BaseException, Type, 0),
    builtin!(BaseExceptionGroup, Type, 11),
    builtin!(BlockingIOError, Type, 3),
    builtin!(BrokenPipeError, Type, 3),
    builtin!(BufferError, Type, 0),
    builtin!(BytesWarning, Type, 0),
    builtin!(ChildProcessError, Type, 3),
    builtin!(ConnectionAbortedError, Type, 3),
    builtin!(ConnectionError, Type, 3),
    builtin!(ConnectionRefusedError, Type, 3),
    builtin!(ConnectionResetError, Type, 3),
    builtin!(DeprecationWarning, Type, 0),
    builtin!(EOFError, Type, 0),
    builtin!(Ellipsis, Value, 0),
    builtin!(EncodingWarning, Type, 10),
    builtin!(EnvironmentError, Type, 0),
    builtin!(Exception, Type, 0),
    builtin!(ExceptionGroup, Type, 11),
    builtin!(False, Value, 0),
    builtin!(FileExistsError, Type, 3),
    builtin!(FileNotFoundError, Type, 3),
    builtin!(FloatingPointError, Type, 0),
    builtin!(FutureWarning, Type, 0),
    builtin!(GeneratorExit, Type, 0),
    builtin!(IOError, Type, 0),
    builtin!(ImportCycleError, Type, 15),
    builtin!(ImportError, Type, 0),
    builtin!(ImportWarning, Type, 0),
    builtin!(IndentationError, Type, 0),
    builtin!(IndexError, Type, 0),
    builtin!(InterruptedError, Type, 3),
    builtin!(IsADirectoryError, Type, 3),
    builtin!(KeyError, Type, 0),
    builtin!(KeyboardInterrupt, Type, 0),
    builtin!(LookupError, Type, 0),
    builtin!(MemoryError, Type, 0),
    builtin!(ModuleNotFoundError, Type, 6),
    builtin!(NameError, Type, 0),
    builtin!(None, Value, 0),
    builtin!(NotADirectoryError, Type, 3),
    builtin!(NotImplemented, Value, 0),
    builtin!(NotImplementedError, Type, 0),
    builtin!(OSError, Type, 0),
    builtin!(OverflowError, Type, 0),
    builtin!(PendingDeprecationWarning, Type, 0),
    builtin!(PermissionError, Type, 3),
    builtin!(ProcessLookupError, Type, 3),
    builtin!(PythonFinalizationError, Type, 13),
    builtin!(RecursionError, Type, 5),
    builtin!(ReferenceError, Type, 0),
    builtin!(ResourceWarning, Type, 2),
    builtin!(RuntimeError, Type, 0),
    builtin!(RuntimeWarning, Type, 0),
    builtin!(StopAsyncIteration, Type, 5),
    builtin!(StopIteration, Type, 0),
    builtin!(SyntaxError, Type, 0),
    builtin!(SyntaxWarning, Type, 0),
    builtin!(SystemError, Type, 0),
    builtin!(SystemExit, Type, 0),
    builtin!(TabError, Type, 0),
    builtin!(TimeoutError, Type, 3),
    builtin!(True, Value, 0),
    builtin!(TypeError, Type, 0),
    builtin!(UnboundLocalError, Type, 0),
    builtin!(UnicodeDecodeError, Type, 0),
    builtin!(UnicodeEncodeError, Type, 0),
    builtin!(UnicodeError, Type, 0),
    builtin!(UnicodeTranslateError, Type, 0),
    builtin!(UnicodeWarning, Type, 0),
    builtin!(UserWarning, Type, 0),
    builtin!(ValueError, Type, 0),
    builtin!(Warning, Type, 0),
    builtin!(ZeroDivisionError, Type, 0),
    builtin!(__build_class__, Callable, 0),
    builtin!(__debug__, Value, 0),
    builtin!(__import__, Callable, 0),
    builtin!(abs, Callable, 0),
    builtin!(aiter, Callable, 10),
    builtin!(all, Callable, 0),
    builtin!(anext, Callable, 10),
    builtin!(any, Callable, 0),
    builtin!(ascii, Callable, 0),
    builtin!(bin, Callable, 0),
    builtin!(bool, Type, 0),
    builtin!(breakpoint, Callable, 7),
    builtin!(bytearray, Type, 0),
    builtin!(bytes, Type, 0),
    builtin!(callable, Callable, 2),
    builtin!(chr, Callable, 0),
    builtin!(classmethod, Type, 0),
    builtin!(compile, Callable, 0),
    builtin!(complex, Type, 0),
    builtin!(delattr, Callable, 0),
    builtin!(dict, Type, 0),
    builtin!(dir, Callable, 0),
    builtin!(divmod, Callable, 0),
    builtin!(enumerate, Type, 0),
    builtin!(eval, Callable, 0),
    builtin!(exec, Callable, 0),
    builtin!(filter, Type, 0),
    builtin!(float, Type, 0),
    builtin!(format, Callable, 0),
    builtin!(frozendict, Type, 15),
    builtin!(frozenset, Type, 0),
    builtin!(getattr, Callable, 0),
    builtin!(globals, Callable, 0),
    builtin!(hasattr, Callable, 0),
    builtin!(hash, Callable, 0),
    builtin!(hex, Callable, 0),
    builtin!(id, Callable, 0),
    builtin!(input, Callable, 0),
    builtin!(int, Type, 0),
    builtin!(isinstance, Callable, 0),
    builtin!(issubclass, Callable, 0),
    builtin!(iter, Callable, 0),
    builtin!(len, Callable, 0),
    builtin!(list, Type, 0),
    builtin!(locals, Callable, 0),
    builtin!(map, Type, 0),
    builtin!(max, Callable, 0),
    builtin!(memoryview, Type, 0),
    builtin!(min, Callable, 0),
    builtin!(next, Callable, 0),
    builtin!(object, Type, 0),
    builtin!(oct, Callable, 0),
    builtin!(open, Callable, 0),
    builtin!(ord, Callable, 0),
    builtin!(pow, Callable, 0),
    builtin!(print, Callable, 0),
    builtin!(property, Type, 0),
    builtin!(range, Type, 0),
    builtin!(repr, Callable, 0),
    builtin!(reversed, Type, 0),
    builtin!(round, Callable, 0),
    builtin!(sentinel, Type, 15),
    builtin!(set, Type, 0),
    builtin!(setattr, Callable, 0),
    builtin!(slice, Type, 0),
    builtin!(sorted, Callable, 0),
    builtin!(staticmethod, Type, 0),
    builtin!(str, Type, 0),
    builtin!(sum, Callable, 0),
    builtin!(super, Type, 0),
    builtin!(tuple, Type, 0),
    builtin!(type, Type, 0),
    builtin!(vars, Callable, 0),
    builtin!(zip, Type, 0),
];

/// The language rule is independent of the lexical binding named object.
pub fn implicit_base(version: Option<PythonVersion>) -> Option<&'static Builtin> {
    let object = BUILTINS
        .iter()
        .find(|row| row.name == "object")
        .expect("object is a Python language root");
    (object.versions.availability(version) == Availability::Present).then_some(object)
}
pub fn builtin(name: &str) -> Option<&'static Builtin> {
    BUILTINS.iter().find(|row| row.name == name)
}

#[derive(Clone, Copy, Debug)]
pub struct ObjectMember {
    pub name: &'static str,
    pub versions: VersionRange,
}
macro_rules! member {
    ($name:literal, $minor:literal) => {
        ObjectMember {
            name: $name,
            versions: VersionRange {
                since: PythonVersion::new(3, $minor),
            },
        }
    };
}
/// Complete for the audited version interval, including descriptors, not just methods.
pub const OBJECT_MEMBERS: &[ObjectMember] = &[
    member!("__class__", 0),
    member!("__delattr__", 0),
    member!("__dir__", 3),
    member!("__doc__", 0),
    member!("__eq__", 0),
    member!("__format__", 0),
    member!("__ge__", 0),
    member!("__getattribute__", 0),
    member!("__getstate__", 11),
    member!("__gt__", 0),
    member!("__hash__", 0),
    member!("__init__", 0),
    member!("__init_subclass__", 6),
    member!("__le__", 0),
    member!("__lt__", 0),
    member!("__ne__", 0),
    member!("__new__", 0),
    member!("__reduce__", 0),
    member!("__reduce_ex__", 0),
    member!("__repr__", 0),
    member!("__setattr__", 0),
    member!("__sizeof__", 0),
    member!("__str__", 0),
    member!("__subclasshook__", 0),
];

pub fn object_member(name: &str, version: Option<PythonVersion>) -> Availability {
    match OBJECT_MEMBERS.iter().find(|row| row.name == name) {
        Some(row) => row.versions.availability(version),
        None if version.is_none_or(|v| (FIRST..END).contains(&v)) => Availability::Absent,
        None => Availability::Unknown,
    }
}

/// Existing Python value-class policy shared by legacy and native member
/// lookup. Their intrinsic dictionaries cannot acquire user-defined members;
/// rebinding a name in the mutable builtins module is a separate operation.
pub fn has_fixed_value_class_surface(qualified_name: &str) -> bool {
    matches!(
        qualified_name,
        "types.NoneType"
            | "builtins.bool"
            | "builtins.int"
            | "builtins.float"
            | "builtins.str"
            | "builtins.bytes"
            | "builtins.list"
            | "builtins.tuple"
            | "builtins.dict"
            | "builtins.set"
            | "builtins.frozenset"
            | "builtins.object"
    )
}
