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
    let api_version = payload
        .get("api_version")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let mut diagnostics = vec![
        format!("plugin_id={plugin_id}"),
        format!("api_version={api_version}"),
        format!("changed_files={changed_files}"),
    ];
    if let Some(shadow_of) = payload.get("shadow_of").and_then(|value| value.as_str()) {
        diagnostics.push(format!("shadow_of={shadow_of}"));
    }
    if let Some(bridge_mode) = payload
        .get("metadata")
        .and_then(|metadata| metadata.get("bridge_mode"))
        .and_then(|value| value.as_str())
    {
        diagnostics.push(format!("bridge_mode={bridge_mode}"));
    }
    diagnostics.extend(extra_diagnostics);
    let out = json!({
        "findings": [],
        "diagnostics": diagnostics
    });
    println!("{}", out);
}
