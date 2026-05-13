import process from "node:process";

const chunks = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk);
}
const raw = Buffer.concat(chunks).toString("utf8").trim();
let payload = { changed_files: [] };
const extraDiagnostics = [];
if (raw.length !== 0) {
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    extraDiagnostics.push(
      `invalid json input: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
const diagnostics = [
  `plugin_id=${payload.plugin_id ?? "sample"}`,
  `api_version=${payload.api_version ?? "unknown"}`,
  `changed_files=${(payload.changed_files ?? []).length}`,
  ...extraDiagnostics,
];
if (typeof payload.shadow_of === "string") {
  diagnostics.push(`shadow_of=${payload.shadow_of}`);
}
if (typeof payload.metadata?.bridge_mode === "string") {
  diagnostics.push(`bridge_mode=${payload.metadata.bridge_mode}`);
}
process.stdout.write(JSON.stringify({ findings: [], diagnostics }));
