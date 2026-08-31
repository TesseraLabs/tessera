import fs from 'node:fs';
import path from 'node:path';

function openSpecRequirements(productRoot) {
  const root = path.join(productRoot, 'openspec', 'specs');
  if (!fs.existsSync(root)) return [];
  const rows = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory()) continue;
    const file = path.join(root, entry.name, 'spec.md');
    if (!fs.existsSync(file)) continue;
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    for (let index = 0; index < lines.length; index++) {
      const match = /^### Requirement:\s*(.+?)\s*$/.exec(lines[index]);
      if (!match) continue;
      const title = match[1];
      rows.push({ key: `${entry.name}::${title}`, capability: entry.name, title, file: `openspec/specs/${entry.name}/spec.md`, line: index + 1 });
    }
  }
  return rows;
}

/** Сравнивает каждое OpenSpec requirement с co-located origins норм spec2. */
export function buildOpenSpecCoverage(repo) {
  const legacy = openSpecRequirements(repo.productRoot);
  const legacyByKey = new Map(legacy.map((row) => [row.key, row]));
  const claims = new Map();
  for (const [id, { file, req }] of repo.requirementsById) {
    for (const origin of req.origins || []) {
      if (!claims.has(origin)) claims.set(origin, []);
      claims.get(origin).push({ id, file: file.path });
    }
  }
  const rows = legacy.map((source) => {
    const targets = claims.get(source.key) || [];
    return { ...source, coverage: targets.length === 0 ? 'missing' : targets.length === 1 ? 'covered' : 'duplicate', targets };
  });
  const unknown = [];
  for (const [origin, targets] of claims) if (!legacyByKey.has(origin)) unknown.push({ origin, targets });
  const counts = { covered: 0, missing: 0, duplicate: 0, unknown: unknown.length };
  for (const row of rows) counts[row.coverage]++;
  const capabilities = [...new Set(legacy.map((row) => row.capability))].sort().map((capability) => {
    const subset = rows.filter((row) => row.capability === capability);
    return {
      capability,
      total: subset.length,
      covered: subset.filter((row) => row.coverage === 'covered').length,
      missing: subset.filter((row) => row.coverage === 'missing').length,
      duplicate: subset.filter((row) => row.coverage === 'duplicate').length,
    };
  });
  return { total: rows.length, counts, capabilities, rows, unknown };
}

export function formatOpenSpecCoverage(report, { missingOnly = false } = {}) {
  const lines = [
    `OpenSpec → spec2: ${report.counts.covered}/${report.total} covered; ${report.counts.missing} missing; ${report.counts.duplicate} duplicate; ${report.counts.unknown} unknown origins`,
  ];
  for (const item of report.capabilities) {
    if (missingOnly && item.missing === 0 && item.duplicate === 0) continue;
    lines.push(`- ${item.capability}: ${item.covered}/${item.total}${item.missing ? `; missing ${item.missing}` : ''}${item.duplicate ? `; duplicate ${item.duplicate}` : ''}`);
  }
  if (missingOnly) {
    for (const row of report.rows.filter((item) => item.coverage !== 'covered')) {
      lines.push(`  - [${row.coverage}] ${row.key}${row.targets.length ? ` → ${row.targets.map((target) => target.id).join(', ')}` : ''}`);
    }
    for (const row of report.unknown) lines.push(`  - [unknown] ${row.origin} → ${row.targets.map((target) => target.id).join(', ')}`);
  }
  return lines.join('\n');
}
