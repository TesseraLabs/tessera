import fs from 'node:fs';
import path from 'node:path';
import { parseYAML } from './yaml.mjs';

function yamlFiles(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) out.push(...yamlFiles(full));
    else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) out.push(full);
  }
  return out.sort();
}

/**
 * Проверяет не старый openspec requirement, а реальную связность E2E-кейса со
 * spec2 evidence. Файловый test-якорь считается coarse, `#CASE-ID` — exact.
 */
export function auditE2E(repo) {
  const casesRoot = path.join(repo.productRoot, 'tests', 'e2e', 'cases');
  const evidence = [];
  for (const [reqId, { req }] of repo.requirementsById) {
    for (const anchor of req.evidenceAnchors) {
      if (anchor.type === 'test' && anchor.file.startsWith('tests/e2e/cases/')) {
        evidence.push({ reqId, file: anchor.file, symbol: anchor.symbol || null });
      }
    }
  }

  const rows = [];
  for (const abs of yamlFiles(casesRoot)) {
    const file = path.relative(repo.productRoot, abs).split(path.sep).join('/');
    let parsed;
    try {
      parsed = parseYAML(fs.readFileSync(abs, 'utf8'), 1);
    } catch (error) {
      rows.push({ file, id: null, title: null, legacyRequirement: null, coverage: 'invalid', requirements: [], error: error.message });
      continue;
    }
    for (const item of Array.isArray(parsed?.cases) ? parsed.cases : []) {
      if (!item || typeof item !== 'object') continue;
      const id = item.id ? String(item.id) : null;
      const exact = evidence.filter((a) => a.file === file && a.symbol === id);
      const coarse = evidence.filter((a) => a.file === file && !a.symbol);
      const matches = exact.length > 0 ? exact : coarse;
      rows.push({
        file,
        id,
        title: item.title ? String(item.title) : null,
        legacyRequirement: item.requirement ? String(item.requirement) : null,
        coverage: exact.length > 0 ? 'exact' : coarse.length > 0 ? 'coarse' : 'missing',
        requirements: [...new Set(matches.map((a) => a.reqId))].sort(),
        error: null,
      });
    }
  }
  const counts = { exact: 0, coarse: 0, missing: 0, invalid: 0 };
  for (const row of rows) counts[row.coverage]++;
  return { rows, counts, total: rows.length };
}

export function formatE2EAudit(report, { missingOnly = false } = {}) {
  const visible = missingOnly ? report.rows.filter((row) => row.coverage !== 'exact') : report.rows;
  const lines = [
    `E2E ↔ spec2: всего ${report.total}; exact ${report.counts.exact}; coarse ${report.counts.coarse}; missing ${report.counts.missing}; invalid ${report.counts.invalid}`,
  ];
  if (missingOnly) {
    const groups = new Map();
    for (const row of visible) {
      if (!groups.has(row.file)) groups.set(row.file, { statuses: new Set(), ids: [], requirements: new Set(), errors: new Set() });
      const group = groups.get(row.file);
      group.statuses.add(row.coverage);
      if (row.id) group.ids.push(row.id);
      for (const req of row.requirements) group.requirements.add(req);
      if (row.error) group.errors.add(row.error);
    }
    for (const [file, group] of groups) {
      const suffix = group.requirements.size ? ` → ${[...group.requirements].sort().join(', ')}` : '';
      lines.push(`- [${[...group.statuses].sort().join('+')}] ${file}: ${group.ids.join(', ') || '?'}${suffix}`);
      for (const error of group.errors) lines.push(`  - ${error}`);
    }
    return lines.join('\n');
  }
  for (const row of visible) {
    lines.push(`- [${row.coverage}] ${row.id || '?'} — ${row.file}${row.requirements.length ? ` → ${row.requirements.join(', ')}` : ''}${row.error ? ` (${row.error})` : ''}`);
  }
  return lines.join('\n');
}
