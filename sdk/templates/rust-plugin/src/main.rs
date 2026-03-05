use serde_json::json;
use std::io::Read;

fn main() {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).unwrap();
    let changed_files = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("changed_files").and_then(|c| c.as_array().map(|a| a.len())))
        .unwrap_or(0);
    let out = json!({
        "findings": [],
        "diagnostics": [
            "plugin_id=sample",
            format!("changed_files={}", changed_files)
        ]
    });
    println!("{}", out);
}
