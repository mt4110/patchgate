import process from "node:process";

const chunks = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk);
}
const raw = Buffer.concat(chunks).toString("utf8").trim();
const payload = raw.length === 0 ? { changed_files: [] } : JSON.parse(raw);
const diagnostics = [
  `plugin_id=${payload.plugin_id ?? "unknown"}`,
  `changed_files=${(payload.changed_files ?? []).length}`,
];
process.stdout.write(JSON.stringify({ findings: [], diagnostics }));
