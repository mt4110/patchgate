use serde_json::{json, Value};
use std::io::Read;

fn main() {
    let mut raw = String::new();
    let mut extra_diagnostics = Vec::new();
    if let Err(err) = std::io::stdin().read_to_string(&mut raw) {
        extra_diagnostics.push(format!("stdin read failed: {err}"));
    }
    let payload = if raw.trim().is_empty() {
        Value::Null
    } else {
        match serde_json::from_str::<Value>(&raw) {
            Ok(payload) => payload,
            Err(err) => {
                extra_diagnostics.push(format!("invalid json input: {err}"));
                Value::Null
            }
        }
    };
    let changed_files = payload
        .get("changed_files")
        .and_then(|c| c.as_array().map(|a| a.len()))
        .unwrap_or(0);
    let plugin_id = payload
        .get("plugin_id")
        .and_then(|value| value.as_str())
        .unwrap_or("sample");
    let mut diagnostics = vec![
        format!("plugin_id={plugin_id}"),
        format!("changed_files={changed_files}"),
    ];
    diagnostics.extend(extra_diagnostics);
    let out = json!({
        "findings": [],
        "diagnostics": diagnostics
    });
    println!("{}", out);
}
