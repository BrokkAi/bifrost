pub fn format_value(value: i32) -> i32 {
    value * 2
}

pub fn unused() -> i32 {
    0
}

pub struct Config;

impl Config {
    pub fn new() -> Config {
        Config
    }
}
