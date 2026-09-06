// Serialize a `HuntCatalogEntry` back into the same YAML shape the loader
// accepts. Used for "View details" (read-only preview) and "Clone to user
// rule" (pre-fill the editor with a built-in rule's body).

import type { HuntCatalogEntry } from "./ipc";

export function entryToYaml(entry: HuntCatalogEntry, opts?: { clone?: boolean }): string {
  const clone = opts?.clone ?? false;

  const lines: string[] = [];
  // When cloning a built-in, append `.copy` to the id so we don't override
  // the built-in by accident.
  const id = clone ? `${entry.id}.copy` : entry.id;
  lines.push(`id: ${yamlString(id)}`);
  lines.push(`title: ${yamlString(clone ? `${entry.title} (copy)` : entry.title)}`);
  if (entry.description && entry.description.trim()) {
    lines.push("description: |");
    for (const l of entry.description.split("\n")) {
      lines.push(`  ${l}`);
    }
  }
  lines.push(`severity: ${entry.severity.toLowerCase()}`);
  if (entry.mitre.length > 0) {
    lines.push(`mitre:`);
    for (const m of entry.mitre) lines.push(`  - ${yamlString(m)}`);
  }
  if (entry.references.length > 0) {
    lines.push(`references:`);
    for (const r of entry.references) lines.push(`  - ${yamlString(r)}`);
  }

  const q = entry.query;
  lines.push(`detection:`);
  lines.push(`  kind: ${q.kind}`);
  switch (q.kind) {
    case "events_where":
    case "dns_where":
      if (q.where_sql != null) {
        lines.push(`  where: |`);
        for (const l of q.where_sql.split("\n")) lines.push(`    ${l}`);
      }
      if (q.max_per_run != null) lines.push(`  max_per_run: ${q.max_per_run}`);
      break;
    case "events_grouped":
      if (q.where_sql != null) {
        lines.push(`  where: |`);
        for (const l of q.where_sql.split("\n")) lines.push(`    ${l}`);
      }
      if (q.group_by != null) lines.push(`  group_by: ${q.group_by}`);
      if (q.min_count != null) lines.push(`  min_count: ${q.min_count}`);
      if (q.max_per_run != null) lines.push(`  max_per_run: ${q.max_per_run}`);
      break;
    case "custom":
      if (q.select_sql != null) {
        lines.push(`  select: |`);
        for (const l of q.select_sql.split("\n")) lines.push(`    ${l}`);
      }
      break;
  }

  return lines.join("\n") + "\n";
}

/** Conservative YAML scalar quoting: always wrap in double quotes if the
 *  value contains characters that could be YAML-interpreted (`:`, `#`, etc.).
 *  Safe for our IDs, titles, refs. */
function yamlString(v: string): string {
  if (/^[A-Za-z0-9._\-/]+$/.test(v)) return v;
  return JSON.stringify(v);
}

/** Suggest a filename for the clone operation. Replaces dots with `-` and
 *  appends `.yml`. */
export function cloneFilename(entry: HuntCatalogEntry): string {
  const safe = entry.id.replace(/[^\w.-]/g, "_");
  return `${safe}.copy.yml`;
}
