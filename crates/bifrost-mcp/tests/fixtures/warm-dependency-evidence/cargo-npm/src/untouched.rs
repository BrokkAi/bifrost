use serde_json::Value;
trait Runner { fn run(&self); }
struct Local;
impl Runner for Local { fn run(&self) {} }
pub fn check<T: Runner>(runner: T) {
 runner.run();
 let _ = serde_json::to_string(&Value::Null);
}
