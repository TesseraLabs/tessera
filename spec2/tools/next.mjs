import { buildDoctorReport } from './doctor.mjs';
import { buildQualityReport } from './quality.mjs';

function priority(score) {
  if (score >= 95) return 'P0';
  if (score >= 80) return 'P1';
  if (score >= 60) return 'P2';
  return 'P3';
}

function item(score, code, title, detail, action, location = null, count = 1) {
  return { score, priority: priority(score), code, title, detail, action, location, count };
}

function groupedQuality(report, code, score, title, action) {
  const rows = report.rows.filter((row) => row.code === code);
  if (!rows.length) return null;
  const sample = rows.slice(0, 3).map((row) => row.requirement || `${row.path}:${row.line}`).join(', ');
  return item(score, code, title, `${rows.length} сигналов; первые: ${sample}`, action, null, rows.length);
}

/** Приоритизированная очередь долга, вычисленная из текущего состояния спеки. */
export function buildNextQueue(repo) {
  const doctor = buildDoctorReport(repo);
  const quality = buildQualityReport(repo);
  const items = [];

  const combinationFindings = doctor.lint.findings.filter((finding) => finding.code.startsWith('W-COMBINATIONS-UNDEFINED'));
  if (combinationFindings.length) {
    const representative = combinationFindings.find((finding) => finding.code.endsWith('COVERAGE')) || combinationFindings[0];
    items.push(item(92, 'COMBINATIONS-UNDEFINED', representative.message,
      combinationFindings.map((finding) => finding.code).join(', '),
      'принять доменное решение, заполнить outcome и повторить spec.mjs lint',
      `${representative.path}:${representative.line}`));
  }
  for (const finding of doctor.lint.findings.filter((entry) => !entry.code.startsWith('W-COMBINATIONS-UNDEFINED'))) {
    const score = finding.level === 'ERROR' ? 100 : 76;
    items.push(item(score, finding.code, finding.message, `${finding.path}:${finding.line}`, 'исправить lint-находку и повторить spec.mjs lint', `${finding.path}:${finding.line}`));
  }

  for (const row of doctor.trace.rows) {
    items.push(item(96, 'TRACE-GAP', `${row.id}: разрыв трассировки`, row.gaps.join(', '), `spec.mjs context ${row.id} --slice implement`, row.owner.path));
  }

  for (const check of doctor.outcomes.checks.filter((entry) => entry.status !== 'ok')) {
    const discrepancy = check.status === 'discrepancy';
    items.push(item(discrepancy ? 98 : 82, `OUTCOME-${check.status.toUpperCase()}`, `${check.id}: ${discrepancy ? 'расхождение исходов' : 'сверка исходов не состоялась'}`, check.text.split('\n')[0], `spec.mjs outcomes ${check.id}`, null));
  }

  for (const row of quality.rows.filter((entry) => entry.code === 'W-UNRESOLVED-CLAIM')) {
    items.push(item(88, row.code, 'Разрешить утверждение о долге или реализации', row.message, row.action, `${row.path}:${row.line}`));
  }
  const qualityGroups = [
    groupedQuality(quality, 'W-SELF-ONLY-SUBJECT', 68, 'Назвать реальные носители норм', 'spec.mjs quality --all'),
    groupedQuality(quality, 'W-GENERIC-NORM', 64, 'Переписать миграционные нормы как самостоятельные предикаты', 'spec.mjs quality --all'),
    groupedQuality(quality, 'W-COARSE-EVIDENCE', 58, 'Уточнить test evidence до CASE-ID или символа', 'spec.mjs e2e --missing'),
    groupedQuality(quality, 'W-BROAD-CODE-ANCHOR', 38, 'Уточнить code-якоря до символов', 'spec.mjs quality --all'),
  ];
  items.push(...qualityGroups.filter(Boolean));

  if (doctor.openspec.counts.missing || doctor.openspec.counts.duplicate || doctor.openspec.counts.unknown) {
    const count = doctor.openspec.counts.missing + doctor.openspec.counts.duplicate + doctor.openspec.counts.unknown;
    items.push(item(94, 'OPENSPEC-COVERAGE', 'Восстановить однозначное покрытие OpenSpec', `${count} проблем миграции`, 'spec.mjs coverage --missing', null, count));
  }
  if (doctor.e2e.counts.invalid) {
    items.push(item(97, 'E2E-INVALID', 'Исправить неразбираемые E2E-кейсы', `${doctor.e2e.counts.invalid} invalid`, 'spec.mjs e2e --missing', null, doctor.e2e.counts.invalid));
  }
  if (doctor.e2e.counts.missing) {
    items.push(item(72, 'E2E-MISSING', 'Связать E2E-кейсы с нормами spec2', `${doctor.e2e.counts.missing} кейсов без evidence`, 'spec.mjs e2e --missing', null, doctor.e2e.counts.missing));
  }
  if (doctor.e2e.counts.coarse) {
    items.push(item(52, 'E2E-COARSE', 'Сделать связи E2E точными', `${doctor.e2e.counts.coarse} кейсов покрыты только файловым якорем`, 'spec.mjs e2e --missing', null, doctor.e2e.counts.coarse));
  }
  if (doctor.candidates.pending) {
    items.push(item(32, 'CANDIDATES', 'Разобрать кандидаты доменного словаря', `${doctor.candidates.pending} кандидатов без вердикта`, 'spec.mjs candidates --new', null, doctor.candidates.pending));
  }

  items.sort((a, b) => b.score - a.score || a.code.localeCompare(b.code) || String(a.location).localeCompare(String(b.location)));
  const counts = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const entry of items) counts[entry.priority]++;
  return { status: items.length ? 'work' : 'clear', total: items.length, counts, items };
}

export function formatNextQueue(report, { all = false, limit = 10 } = {}) {
  const visible = all ? report.items : report.items.slice(0, limit);
  const lines = [
    `NEXT: ${report.total} пунктов (${Object.entries(report.counts).map(([key, value]) => `${key} ${value}`).join(' / ')})`,
  ];
  if (!visible.length) return `${lines[0]}\nОчередь пуста.`;
  for (const entry of visible) {
    lines.push(`- [${entry.priority}] ${entry.code} — ${entry.title}${entry.count > 1 ? ` (${entry.count})` : ''}`);
    lines.push(`  ${entry.detail}`);
    if (entry.location) lines.push(`  где: ${entry.location}`);
    lines.push(`  → ${entry.action}`);
  }
  if (!all && report.items.length > visible.length) lines.push('', `Ещё ${report.items.length - visible.length}: spec.mjs next --all`);
  return lines.join('\n');
}
