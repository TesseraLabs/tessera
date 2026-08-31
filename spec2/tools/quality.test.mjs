import test from 'node:test';
import assert from 'node:assert/strict';

import { buildQualityReport, formatQualityReport } from './quality.mjs';

test('quality отделяет семантическую слабость от синтаксического lint', () => {
  const file = {
    path: 'operations/check.md',
    frontmatter: { id: 'check', context: 'auth', kind: 'операция' },
    frontmatterStartLine: 2,
    bodyStartLine: 20,
    frontmatterAnchors: [{ type: 'code', target: 'src/check.rs', symbol: null }],
    requirements: [{
      id: 'AUTH-001', headingLine: 24, sectionStart: 24, sectionEnd: 31,
      subjects: ['auth.check'],
      evidenceAnchors: [
        { type: 'test', target: 'tests/check.yaml', symbol: null },
        { type: 'code', target: 'src/check.rs', symbol: null },
      ],
    }],
    norms: [{ startLine: 26, sentenceText: '[[auth.check]] MUST соблюдать правило «Check» вместе со всеми условиями ниже.' }],
    maskedLines: ['# Check', '', '', '', '', '', '', '', '', '', '', 'KNOWN GAP: поведение не реализовано'],
  };
  const report = buildQualityReport({ files: [file] });
  assert.equal(report.counts['W-SELF-ONLY-SUBJECT'], 1);
  assert.equal(report.counts['W-GENERIC-NORM'], 1);
  assert.equal(report.counts['W-COARSE-EVIDENCE'], 1);
  assert.equal(report.counts['W-BROAD-CODE-ANCHOR'], 2);
  assert.equal(report.counts['W-UNRESOLVED-CLAIM'], 1);
  assert.deepEqual(report.severityCounts, { high: 1, medium: 3, low: 2 });
  assert.match(formatQualityReport(report), /Детализация/);
  assert.match(formatQualityReport(report, { all: true }), /AUTH-001/);
});
