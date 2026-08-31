import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { loadRepo, buildGraph } from 'spec9/graph';
import { buildReviewImpact } from 'spec9/impact';
import { buildChangeReport, formatChangeReport } from 'spec9/change';
import { buildNextQueue } from 'spec9/next';
import { traceFlow } from 'spec9/flow';
import { lint } from 'spec9/lint';
import { draftPage } from 'spec9/draft';

const specRoot = path.resolve(import.meta.dirname, '..');
const productRoot = path.dirname(specRoot);
const repo = () => loadRepo(specRoot, productRoot);

test('code impact ведёт к контексту и норме', () => {
  const report = buildReviewImpact(repo(), ['crates/tessera_core/src/crl/store.rs']);
  const auth = report.contexts.find((context) => context.id === 'auth');
  assert.ok(auth?.requirements.some((requirement) => requirement.id === 'REV-004'));
  assert.deepEqual(report.unmappedFiles, []);
});

test('change report содержит проверки и Domain impact', () => {
  const report = buildChangeReport(repo(), ['crates/tessera_core/src/crl/store.rs']);
  assert.ok(report.affectedRequirements.includes('REV-004'));
  assert.ok(report.checks.includes('spec9 lint'));
  assert.ok(report.checks.includes('spec9 decision auth.ADR-001'));
  assert.match(formatChangeReport(report), /## Domain impact/);
  assert.ok(buildChangeReport(repo(), ['spec9/terms/auth/revocation-check.md']).checks.includes('spec9 coverage --missing'));
});

test('очередь долга Tessera сортируется по риску', () => {
  const report = buildNextQueue(repo());
  assert.ok(report.total > 0);
  assert.ok(report.items.every((entry, index) => index === 0 || report.items[index - 1].score >= entry.score));
});

test('review impact не теряет ADR без собственных requirements', () => {
  const report = buildReviewImpact(repo(), ['spec9/decisions/ADR-001-crl-signature-verified.md']);
  const auth = report.contexts.find((context) => context.id === 'auth');
  assert.ok(auth?.terms.some((term) => term.id === 'auth.ADR-001'));
  assert.ok(auth?.decisions.includes('auth.ADR-001'));
});

test('причинные срезы связывают входы с состоянием и артефактами', () => {
  const login = traceFlow(repo(), 'pam-conversation').edges.map((edge) => `${edge.from}:${edge.relation}:${edge.to}`);
  assert.ok(login.includes('pam-conversation:starts:pkcs12-login'));
  assert.ok(login.includes('open-monitored-session:writes:session-registry'));
  const issuance = traceFlow(repo(), 'issuer-cli').edges.map((edge) => `${edge.from}:${edge.relation}:${edge.to}`);
  assert.ok(issuance.includes('issuer-cli:starts:leaf-certificate-issuance'));
  assert.ok(issuance.includes('issue-leaf-certificate:produces:credential'));
  assert.ok(issuance.includes('issue-leaf-certificate:writes:issuance-journal'));
});

test('draft использует профиль и ничего не записывает', () => {
  const draft = draftPage(repo(), 'процесс', 'issuance.future-flow', 'Будущий процесс');
  assert.match(draft, /id: future-flow/);
  assert.match(draft, /outcomes:/);
  assert.ok(!fs.existsSync(path.join(specRoot, 'processes/issuance/future-flow.md')));
});

test('реальная спецификация валидна и не содержит старой разметки', () => {
  const loaded = repo();
  assert.deepEqual(lint(loaded).filter((finding) => finding.level === 'ERROR'), []);
  const graph = buildGraph(loaded);
  assert.ok(graph.nodes.length >= 80);
  assert.ok(graph.edges.length >= 300);
  for (const file of loaded.files) {
    assert.doesNotMatch(file.raw, /\[\[[^\]]+:[^\]]+\]\]/, file.path);
    assert.doesNotMatch(file.raw, /\{#[A-Za-z]/, file.path);
    assert.doesNotMatch(file.raw, /^\*\*(?:Evidence|Outcomes|Partition)/m, file.path);
    assert.doesNotMatch(file.raw, /^\s+version:\s*\d+/m, file.path);
  }
});
