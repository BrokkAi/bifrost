use crate::util;
use crate::util::Config;
use crate::util::format_value;

pub fn run() -> i32 {
    format_value(1)
}

pub fn run_twice() -> i32 {
    let first = format_value(1);
    let second = format_value(2);
    first + second
}

pub fn via_namespace() -> i32 {
    util::format_value(3)
}

pub fn make_config() -> Config {
    Config::new()
}

pub fn shadowed(format_value: i32) -> i32 {
    // `format_value` is the parameter, not the import; referencing it must not
    // produce a shadowed -> util.format_value edge.
    format_value
}

pub fn typed_param(config: Config) -> Config {
    // The parameter's *type* `Config` must not be shadowed by the `config`
    // binding, so the associated call still resolves.
    let _ = config;
    Config::new()
}

pub fn let_shadows() -> i32 {
    // This `let` shadow is local to this function; it must not leak to siblings
    // such as `run`, which still resolves the import.
    let format_value = 5;
    format_value
}

pub fn recurse(n: i32) -> i32 {
    if n <= 0 {
        return 0;
    }
    recurse(n - 1)
}
