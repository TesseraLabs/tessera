import { buildGraph } from './graph.mjs';
import { lint } from './lint.mjs';
import { buildTrace } from './trace.mjs';
import { pendingCandidates } from './candidates-cmd.mjs';
import { cmdOutcomes } from './outcomes-cmd.mjs';
import { auditE2E } from './e2e-audit.mjs';
import { buildOpenSpecCoverage } from './openspec-coverage.mjs';
import { buildQualityReport } from './quality.mjs';

export function buildDoctorReport(repo) {
  const findings = lint(repo);
  const lintErrors = findings.filter((item) => item.level === 'ERROR');
  const lintWarnings = findings.filter((item) => item.level === 'WARN');
  const traceGaps = buildTrace(repo, { missingOnly: true });
  const candidates = pendingCandidates(repo);
  const outcomeChecks = [];
  for (const [id, { req }] of repo.requirementsById) {
    if (!req.outcomes) continue;
    const result = cmdOutcomes(repo, id);
    outcomeChecks.push({ id, status: result.status, text: result.text });
  }
  const e2e = auditE2E(repo);
  const openspec = buildOpenSpecCoverage(repo);
  const quality = buildQualityReport(repo);
  const graph = buildGraph(repo);
  const outcomeCounts = { ok: 0, discrepancy: 0, unchecked: 0 };
  for (const check of outcomeChecks) outcomeCounts[check.status]++;
  const status = lintErrors.length || traceGaps.length || outcomeCounts.discrepancy
    ? 'error'
    : lintWarnings.length || quality.total || candidates.length || outcomeCounts.unchecked || e2e.counts.coarse || e2e.counts.missing || e2e.counts.invalid || openspec.counts.missing || openspec.counts.duplicate || openspec.counts.unknown
      ? 'warn'
      : 'ok';
  return {
    status,
    graph: { nodes: graph.nodes.length, edges: graph.edges.length },
    lint: { errors: lintErrors.length, warnings: lintWarnings.length, findings },
    quality,
    trace: { gaps: traceGaps.length, rows: traceGaps },
    outcomes: { ...outcomeCounts, checks: outcomeChecks },
    candidates: { pending: candidates.length, rows: candidates },
    e2e,
    openspec,
  };
}

export function formatDoctorReport(report) {
  const lines = [
    `SPEC2 DOCTOR: ${report.status.toUpperCase()}`,
    `graph       ${report.graph.nodes} nodes / ${report.graph.edges} edges`,
    `lint        ${report.lint.errors} errors / ${report.lint.warnings} warnings`,
    `quality     ${report.quality.total} signals / ${report.quality.severityCounts.high} high`,
    `trace       ${report.trace.gaps} gaps`,
    `outcomes    ${report.outcomes.ok} ok / ${report.outcomes.discrepancy} discrepancy / ${report.outcomes.unchecked} unchecked`,
    `candidates  ${report.candidates.pending} pending`,
    `e2e         ${report.e2e.counts.exact} exact / ${report.e2e.counts.coarse} coarse / ${report.e2e.counts.missing} missing / ${report.e2e.counts.invalid} invalid`,
    `openspec    ${report.openspec.counts.covered}/${report.openspec.total} covered / ${report.openspec.counts.missing} missing / ${report.openspec.counts.duplicate} duplicate`,
  ];
  if (report.lint.findings.length) {
    lines.push('', 'Lint:');
    for (const item of report.lint.findings) lines.push(`- ${item.code}: ${item.message}`);
  }
  if (report.quality.total) {
    const summary = Object.entries(report.quality.counts).filter(([, count]) => count).map(([code, count]) => `${code}=${count}`).join(', ');
    lines.push('', `Quality: ${summary}`, 'Детализация: spec.mjs quality --all');
  }
  const nonOk = report.outcomes.checks.filter((check) => check.status !== 'ok');
  if (nonOk.length) lines.push('', `Outcomes: ${nonOk.map((item) => `${item.id}=${item.status}`).join(', ')}`);
  if (report.candidates.rows.length) lines.push('', 'Candidates:', ...report.candidates.rows.map((item) => `- ${item.key} (weight ${item.weight})`));
  if (report.e2e.counts.coarse || report.e2e.counts.missing || report.e2e.counts.invalid) {
    lines.push('', 'E2E детализация: spec.mjs e2e --missing');
  }
  if (report.openspec.counts.missing || report.openspec.counts.duplicate || report.openspec.counts.unknown) {
    lines.push('OpenSpec детализация: spec.mjs coverage --missing');
  }
  return lines.join('\n');
}
