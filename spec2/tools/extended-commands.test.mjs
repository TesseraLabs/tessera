import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { auditE2E, formatE2EAudit } from './e2e-audit.mjs';
import { buildRustWorkspaceResolver } from './rust-workspace.mjs';
import { loadRepo } from './graph.mjs';
import { buildReviewImpact } from './review-impact.mjs';
import { buildOpenSpecCoverage } from './openspec-coverage.mjs';
import { buildNextQueue } from './next.mjs';
import { buildChangeReport, formatChangeReport } from './change.mjs';

function write(root, relative, text) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text, 'utf8');
}

test('e2e audit различает exact, coarse и missing и группирует --missing по suite', () => {
  const productRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'spec2-e2e-'));
  write(productRoot, 'tests/e2e/cases/sample.yaml', `
suite: sample
cases:
  - { id: A, title: Exact, requirement: openspec/specs/a/spec.md }
  - { id: B, title: Coarse, requirement: openspec/specs/a/spec.md }
  - { id: C, title: Missing, requirement: openspec/specs/a/spec.md }
`);
  write(productRoot, 'tests/e2e/cases/missing.yaml', `
suite: missing
cases:
  - { id: D, title: Missing, requirement: openspec/specs/d/spec.md }
`);
  const requirementsById = new Map([
    ['REQ-EXACT', { req: { evidenceAnchors: [{ type: 'test', file: 'tests/e2e/cases/sample.yaml', symbol: 'A' }] } }],
    ['REQ-COARSE', { req: { evidenceAnchors: [{ type: 'test', file: 'tests/e2e/cases/sample.yaml', symbol: null }] } }],
  ]);
  const report = auditE2E({ productRoot, requirementsById });
  assert.deepEqual(report.counts, { exact: 1, coarse: 2, missing: 1, invalid: 0 });
  assert.equal(report.rows.find((row) => row.id === 'A').coverage, 'exact');
  assert.equal(report.rows.find((row) => row.id === 'B').coverage, 'coarse');
  const compact = formatE2EAudit(report, { missingOnly: true });
  assert.equal((compact.match(/sample\.yaml/g) || []).length, 1);
  assert.match(compact, /B, C/);
});

test('rust workspace resolver выбирает тип по crate и module из use-path', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'spec2-rust-workspace-'));
  write(root, 'crates/tessera_core/src/error.rs', 'pub enum TrustError { Generic }\n');
  write(root, 'crates/tessera_core/src/x509/error.rs', 'pub enum TrustError { Revoked, Unavailable }\n');
  const resolve = buildRustWorkspaceResolver(root);
  const result = resolve('TrustError', {
    sourceFile: 'crates/pam/src/flow.rs',
    source: 'use tessera_core::x509::TrustError;\n',
  });
  assert.deepEqual(result.variants, ['Revoked', 'Unavailable']);
  assert.match(result.file, /x509\/error\.rs$/);
});

test('review impact реальной Tessera идёт от code-файла к контексту и норме', () => {
  const specRoot = path.resolve(import.meta.dirname, '..');
  const repo = loadRepo(specRoot, path.dirname(specRoot));
  const report = buildReviewImpact(repo, ['crates/tessera_core/src/crl/store.rs']);
  const auth = report.contexts.find((ctx) => ctx.id === 'auth');
  assert.ok(auth);
  assert.ok(auth.requirements.some((req) => req.id === 'REV-004'));
  assert.deepEqual(report.unmappedFiles, []);
});

test('change report добавляет локальные риски и исполняемые проверки', () => {
  const specRoot = path.resolve(import.meta.dirname, '..');
  const repo = loadRepo(specRoot, path.dirname(specRoot));
  const report = buildChangeReport(repo, ['crates/tessera_core/src/crl/store.rs']);
  assert.ok(report.affectedRequirements.includes('REV-004'));
  assert.ok(report.checks.includes('spec.mjs lint'));
  assert.ok(report.checks.includes('spec.mjs decision auth.ADR-001'));
  const formatted = formatChangeReport(report);
  assert.match(formatted, /## Domain impact/);
  assert.match(formatted, /semantic base\/head review/);
  const specChange = buildChangeReport(repo, ['spec2/terms/auth/revocation-check.md']);
  assert.ok(specChange.checks.includes('spec.mjs coverage --missing'));
});

test('next queue реальной Tessera сортирует долг по риску', () => {
  const specRoot = path.resolve(import.meta.dirname, '..');
  const repo = loadRepo(specRoot, path.dirname(specRoot));
  const report = buildNextQueue(repo);
  assert.ok(report.total > 0);
  assert.ok(report.items.every((entry, index) => index === 0 || report.items[index - 1].score >= entry.score));
  assert.ok(report.items.some((entry) => entry.code === 'E2E-MISSING'));
});

test('review impact не теряет ADR без собственных requirements', () => {
  const specRoot = path.resolve(import.meta.dirname, '..');
  const repo = loadRepo(specRoot, path.dirname(specRoot));
  const report = buildReviewImpact(repo, ['spec2/decisions/ADR-001-crl-signature-verified.md']);
  const auth = report.contexts.find((ctx) => ctx.id === 'auth');
  assert.ok(auth);
  assert.ok(auth.terms.some((term) => term.id === 'auth.ADR-001'));
  assert.ok(auth.decisions.includes('auth.ADR-001'));
  assert.deepEqual(report.unmappedFiles, []);
});

test('OpenSpec coverage различает covered, missing, duplicate и unknown origin', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'spec2-openspec-'));
  write(root, 'openspec/specs/sample/spec.md', '# Sample\n\n### Requirement: One\n\n### Requirement: Two\n');
  const requirementsById = new Map([
    ['REQ-1', { file: { path: 'one.md' }, req: { origins: ['sample::One'] } }],
    ['REQ-2', { file: { path: 'two.md' }, req: { origins: ['sample::One', 'sample::Gone'] } }],
  ]);
  const report = buildOpenSpecCoverage({ productRoot: root, requirementsById });
  assert.deepEqual(report.counts, { covered: 0, missing: 1, duplicate: 1, unknown: 1 });
});
