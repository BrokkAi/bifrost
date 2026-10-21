/// Whether one exact builtin exception class is a subtype of another builtin
/// exception class. `None` means either name is outside the known hierarchy.
pub fn python_builtin_exception_is_subclass(name: &str, expected: &str) -> Option<bool> {
    let name = canonical_exception_name(name)?;
    let expected = canonical_exception_name(expected)?;
    if name == expected {
        return Some(true);
    }

    let mut current = name;
    while let Some(parent) = exception_parent(current) {
        if parent == expected {
            return Some(true);
        }
        // ExceptionGroup inherits from both BaseExceptionGroup and Exception.
        if current == "ExceptionGroup" && expected == "Exception" {
            return Some(true);
        }
        current = parent;
    }
    Some(false)
}

/// Return the canonical exception class name when `name` is a builtin exception.
/// Builtin identity itself must be established by the shared lexical identity path.
pub fn python_builtin_exception_name(name: &str) -> Option<&'static str> {
    EXCEPTION_PARENTS
        .iter()
        .find_map(|(exception, _)| (*exception == name).then_some(*exception))
}

fn canonical_exception_name(name: &str) -> Option<&'static str> {
    if matches!(name, "EnvironmentError" | "IOError") {
        return Some("OSError");
    }
    python_builtin_exception_name(name)
}

fn exception_parent(name: &str) -> Option<&'static str> {
    EXCEPTION_PARENTS
        .iter()
        .find_map(|(exception, parent)| (*exception == name).then_some(*parent))
        .flatten()
}

const EXCEPTION_PARENTS: &[(&str, Option<&str>)] = &[
    ("BaseException", None),
    ("BaseExceptionGroup", Some("BaseException")),
    ("Exception", Some("BaseException")),
    ("ExceptionGroup", Some("BaseExceptionGroup")),
    ("GeneratorExit", Some("BaseException")),
    ("KeyboardInterrupt", Some("BaseException")),
    ("SystemExit", Some("BaseException")),
    ("ArithmeticError", Some("Exception")),
    ("FloatingPointError", Some("ArithmeticError")),
    ("OverflowError", Some("ArithmeticError")),
    ("ZeroDivisionError", Some("ArithmeticError")),
    ("AssertionError", Some("Exception")),
    ("AttributeError", Some("Exception")),
    ("BufferError", Some("Exception")),
    ("EOFError", Some("Exception")),
    ("ImportError", Some("Exception")),
    ("ModuleNotFoundError", Some("ImportError")),
    ("LookupError", Some("Exception")),
    ("IndexError", Some("LookupError")),
    ("KeyError", Some("LookupError")),
    ("MemoryError", Some("Exception")),
    ("NameError", Some("Exception")),
    ("UnboundLocalError", Some("NameError")),
    ("OSError", Some("Exception")),
    ("EnvironmentError", Some("OSError")),
    ("IOError", Some("OSError")),
    ("BlockingIOError", Some("OSError")),
    ("ChildProcessError", Some("OSError")),
    ("ConnectionError", Some("OSError")),
    ("BrokenPipeError", Some("ConnectionError")),
    ("ConnectionAbortedError", Some("ConnectionError")),
    ("ConnectionRefusedError", Some("ConnectionError")),
    ("ConnectionResetError", Some("ConnectionError")),
    ("FileExistsError", Some("OSError")),
    ("FileNotFoundError", Some("OSError")),
    ("InterruptedError", Some("OSError")),
    ("IsADirectoryError", Some("OSError")),
    ("NotADirectoryError", Some("OSError")),
    ("PermissionError", Some("OSError")),
    ("ProcessLookupError", Some("OSError")),
    ("TimeoutError", Some("OSError")),
    ("ReferenceError", Some("Exception")),
    ("RuntimeError", Some("Exception")),
    ("NotImplementedError", Some("RuntimeError")),
    ("RecursionError", Some("RuntimeError")),
    ("StopIteration", Some("Exception")),
    ("StopAsyncIteration", Some("Exception")),
    ("SyntaxError", Some("Exception")),
    ("IndentationError", Some("SyntaxError")),
    ("TabError", Some("IndentationError")),
    ("SystemError", Some("Exception")),
    ("TypeError", Some("Exception")),
    ("ValueError", Some("Exception")),
    ("UnicodeError", Some("ValueError")),
    ("UnicodeDecodeError", Some("UnicodeError")),
    ("UnicodeEncodeError", Some("UnicodeError")),
    ("UnicodeTranslateError", Some("UnicodeError")),
    ("Warning", Some("Exception")),
    ("BytesWarning", Some("Warning")),
    ("DeprecationWarning", Some("Warning")),
    ("EncodingWarning", Some("Warning")),
    ("FutureWarning", Some("Warning")),
    ("ImportWarning", Some("Warning")),
    ("PendingDeprecationWarning", Some("Warning")),
    ("ResourceWarning", Some("Warning")),
    ("RuntimeWarning", Some("Warning")),
    ("SyntaxWarning", Some("Warning")),
    ("UnicodeWarning", Some("Warning")),
    ("UserWarning", Some("Warning")),
];
