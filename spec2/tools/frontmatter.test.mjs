import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseYAML, parseFrontmatter } from './yaml.mjs';
import { maskZones, findLinks } from './markdown.mjs';
import { loadRepo, buildGraph, computeObligations } from './graph.mjs';
import { lint } from './lint.mjs';
import { traceFlow } from './flow.mjs';
import { contextSlice } from './slice.mjs';
import { cmdOutcomes } from './outcomes-cmd.mjs';
import { draftPage } from './draft.mjs';
import { buildTrace, formatTrace } from './trace.mjs';
import { decisionIndex, decisionReport, effectiveDecisionStatus } from './decision.mjs';

const PROFILE = `
profile: test
sources: [terms, patterns, events, processes, decisions]
relation_types:
  references: { cardinality: many }
  affects: { cardinality: many, sources: [решение] }
  replaces: { cardinality: many, sources: [решение], targets: [решение] }
  revokes: { cardinality: many, sources: [решение], targets: [решение] }
contexts:
  auth: { title: Auth, prefix: [AUTH] }
  runtime: { title: Runtime, prefix: [RT] }
kinds:
  сущность:
    title: Entity
    anchors: { required: [code, type], optional: [test] }
    links: { may_reference: [сущность, операция, решение, паттерн] }
  операция:
    title: Operation
    anchors: { required: [code, test] }
    links: { may_reference: [сущность, решение, паттерн] }
  событие:
    title: Event
    must: [producer]
    anchors: { required: [test] }
    links: { may_reference: [операция] }
  процесс:
    title: Process
    must: [outcomes]
    anchors: { required: [code, test] }
    links: { may_reference: [сущность, операция] }
  паттерн:
    title: Pattern
    computes_obligations: true
    applicable_to: [сущность, операция]
    anchors: { required: [exemplar] }
  решение:
    title: Decision
    append_only: true
    must: [rejected_alternative]
    lifecycle: [предложено, принято]
    anchors: { required: [] }
non_domain_outcomes: []
outcomes:
  closed: true
  auto_fix: forbidden
  partition_must_be_total: true
  combinations: { require_total: true, require_disjoint: true }
norm_kinds:
  инвариант: { evidence: [test] }
  операционное: { evidence: [test, code], any_of: true }
  разрешение: { evidence: [] }
slices:
  implement:
    seed: [норма]
    follow: [{ edge: субъект, load: full }]
    cross_context: contract_only
budget: { max_files: 25, on_exhaustion: degrade_to_names }
`;

function repository(files, profile = PROFILE) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'spec2-frontmatter-'));
  fs.writeFileSync(path.join(root, 'profile.yaml'), profile);
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(root, relative);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

function entity(id, extra = '', body = '') {
  return `---\nid: ${id}\nkind: сущность\ncontext: auth\nname: ${id}\nno_anchor: { code: external, type: external }\n${extra}---\n\n# ${id}\n\n${body}\n`;
}

function operation({ id = 'check', requirement = '', body = '', extra = '' } = {}) {
  return `---\nid: ${id}\nkind: операция\ncontext: auth\nname: ${id}\nanchors:\n  code: [fixtures/code.rs#run]\n  test: [fixtures/test.yaml]\n${extra}${requirement}---\n\n# ${id}\n\n${body}\n`;
}

function decisionPage({ id, status = 'принято', relations = '  affects: [auth.check]' }) {
  return `---
id: ${id}
kind: решение
context: auth
name: ${id}
status: ${status}
date: 2026-01-01
relations:
${relations}
---
# ${id}

## Контекст

Контекст решения.

## Решение

Выбран вариант.

## Отвергнутые альтернативы

Отвергнут другой вариант.

## Что заставит пересмотреть

Изменение исходных условий.
`;
}

const productFiles = {
  'fixtures/code.rs': 'fn run() {}\n',
  'fixtures/test.yaml': 'ok: true\n',
};

test('полноценный YAML читает block scalar и вложенные структуры', () => {
  const value = parseYAML('description: |\n  первая\n  вторая\nanchors:\n  code: [a.rs#run]\n');
  assert.match(value.description, /первая\nвторая/);
  assert.deepEqual(value.anchors.code, ['a.rs#run']);
});

test('дубли YAML-ключей отклоняются', () => assert.throws(() => parseYAML('id: a\nid: b\n')));

test('frontmatter обязателен и возвращает Markdown отдельно', () => {
  assert.ok(parseFrontmatter('# X').error);
  const parsed = parseFrontmatter('---\nid: x\n---\n\n# X');
  assert.equal(parsed.frontmatter.id, 'x');
  assert.match(parsed.body, /# X/);
});

test('навигационные ссылки не имеют типа и не читаются из code/quote', () => {
  const masked = maskZones(['[[auth.a|A]]', '`[[auth.hidden]]`', '> [[auth.quoted]]']);
  assert.deepEqual(findLinks(masked, 1).map((link) => link.ref), ['auth.a']);
});

test('relations создают графовое ребро, Markdown-ссылка — нет', () => {
  const root = repository({
    'terms/a.md': entity('a', 'relations:\n  references: [auth.b]\n', 'См. [[auth.c|C]].'),
    'terms/b.md': entity('b'),
    'terms/c.md': entity('c'),
  });
  const graph = buildGraph(loadRepo(root));
  assert.ok(graph.edges.some((edge) => edge.from === 'a' && edge.to === 'b' && edge.type === 'relation:references'));
  assert.ok(!graph.edges.some((edge) => edge.from === 'a' && edge.to === 'c'));
});

test('битая relation и битая навигационная ссылка обе видны линту', () => {
  const root = repository({ 'terms/a.md': entity('a', 'relations: { references: [auth.nope] }\n', '[[auth.also-nope]]') });
  assert.equal(lint(loadRepo(root)).filter((finding) => finding.code === 'E-LINK-UNRESOLVED').length, 2);
});

test('межконтекстный ID обязан быть квалифицирован', () => {
  const root = repository({
    'terms/a.md': entity('a', 'relations: { references: [remote] }\n'),
    'terms/remote.md': '---\nid: remote\nkind: сущность\ncontext: runtime\nname: remote\nno_anchor: { code: x, type: x }\n---\n# remote\n',
  });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-LINK-CROSS-CONTEXT'));
});

test('квалифицированная межконтекстная relation разрешается', () => {
  const root = repository({
    'terms/a.md': entity('a', 'relations: { references: [runtime.remote] }\n'),
    'terms/remote.md': '---\nid: remote\nkind: сущность\ncontext: runtime\nname: remote\nno_anchor: { code: x, type: x }\n---\n# remote\n',
  });
  assert.ok(!lint(loadRepo(root)).some((finding) => finding.code.startsWith('E-LINK')));
});

test('требование читается только из frontmatter и связывается с заголовком', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: инвариант\n    subjects: [auth.check]\n    evidence:\n      test: [fixtures/test.yaml]\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — Проверка\n\nПроверка MUST завершаться.' }) });
  const req = loadRepo(root).files.find((file) => file.frontmatter?.id === 'check').requirements[0];
  assert.equal(req.id, 'AUTH-001');
  assert.equal(req.title, 'Проверка');
  assert.deepEqual(req.subjects, ['auth.check']);
  assert.equal(req.evidenceAnchors[0].type, 'test');
});

test('запись требования без Markdown-заголовка — ошибка', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.check]\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-REQ-ID-MISSING'));
});

test('subjects обязателен для каждой нормы', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: []\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\nСистема MAY работать.' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-NORM-NO-SUBJECT'));
});

test('неизвестный тип нормы отклоняется', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: неизвестно\n    subjects: [auth.check]\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-REQ-KIND'));
});

test('evidence берётся из frontmatter и проверяется по kind нормы', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: инвариант\n    subjects: [auth.check]\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-EVIDENCE-MISSING'));
});

test('группированный якорь проверяет файл и символ', () => {
  const root = repository({ ...productFiles, 'terms/check.md': operation() });
  assert.ok(!lint(loadRepo(root)).some((finding) => finding.code === 'E-ANCHOR-BROKEN'));
});

test('опечатка типа якоря не теряется молча', () => {
  const root = repository({ 'terms/a.md': entity('a', 'anchors: { cod: [a.rs#A] }\n') });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-ANCHOR-UNPARSED'));
});

test('субъект требования создаёт отдельное ребро графа', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.a]\n';
  const root = repository({ ...productFiles, 'terms/a.md': entity('a'), 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\nОперация MAY работать.' }) });
  assert.ok(buildGraph(loadRepo(root)).edges.some((edge) => edge.from === 'AUTH-001' && edge.to === 'a' && edge.type === 'субъект'));
});

test('исходы во frontmatter считаются закрытыми и дубли проверяются', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.check]\n    outcomes: [успех, успех]\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-OUTCOMES-DUP'));
});

test('полнота partition хранится во frontmatter', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.check]\n    outcomes: [отказ]\n    partitions:\n      - outcome: отказ\n        total: false\n        classes: [a, b]\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-PARTITION-NOT-TOTAL'));
});

test('combinations во frontmatter проверяются на покрытие', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.check]\n    outcomes: [ok]\ncombinations:\n  - dimensions:\n      mode: [a, b]\n    rows:\n      - when: { mode: a }\n        outcome: ok\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-COMBINATIONS-NOT-TOTAL'));
});

test('outcome null в combinations — явное предупреждение о дыре', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.check]\n    outcomes: [ok]\ncombinations:\n  - dimensions:\n      mode: [a]\n    rows:\n      - when: { mode: a }\n        outcome: null\n';
  const root = repository({ ...productFiles, 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'W-COMBINATIONS-UNDEFINED-ROW'));
});

test('паттерн без версии вычисляет conformance-обязательство', () => {
  const pattern = `---\nid: safe\nkind: паттерн\ncontext: auth\nname: Safe\nanchors: { exemplar: [fixtures/code.rs#run] }\nrequirements:\n  SAFE-001:\n    kind: инвариант\n    subjects: [application]\n---\n# Safe\n### SAFE-001 — Safe\nПрименение MUST быть безопасным.\n`;
  const extra = 'applies:\n  - pattern: safe\nconformance:\n  safe/SAFE-001:\n    test: [fixtures/test.yaml]\n';
  const root = repository({ ...productFiles, 'patterns/safe.md': pattern, 'terms/a.md': entity('a', extra) });
  const repo = loadRepo(root);
  assert.equal(computeObligations(repo.entities.find((entity) => entity.id === 'a'), repo)[0].id, 'a × safe/SAFE-001');
  assert.ok(!lint(repo).some((finding) => finding.code === 'E-PATTERN-OBLIGATION-NO-EVIDENCE'));
});

test('context slice печатает пакет обязательств субъекта один раз при нескольких паттернах', () => {
  const profile = PROFILE.replace(
    'follow: [{ edge: субъект, load: full }]',
    'follow: [{ edge: субъект, load: full }, { edge: применённый-паттерн, load: names }]',
  );
  const pattern = (id, req) => `---
id: ${id}
kind: паттерн
context: auth
name: ${id}
anchors: { exemplar: [fixtures/code.rs#run] }
requirements:
  ${req}:
    kind: инвариант
    subjects: [auth.${id}]
    evidence: { test: [fixtures/test.yaml] }
---
# ${id}
### ${req} — Rule
[[auth.${id}|Pattern]] MUST работать.
`;
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.a]\n';
  const root = repository({
    ...productFiles,
    'patterns/one.md': pattern('one', 'ONE-001'),
    'patterns/two.md': pattern('two', 'TWO-001'),
    'terms/a.md': entity('a', [
      'applies:',
      '  - pattern: one',
      '  - pattern: two',
      'conformance:',
      '  one/ONE-001: { test: [fixtures/test.yaml] }',
      '  two/TWO-001: { test: [fixtures/test.yaml] }',
      '',
    ].join('\n')),
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.a|A]] MAY работать.' }),
  }, profile);
  const slice = contextSlice(loadRepo(root), 'AUTH-001', 'implement');
  assert.equal((slice.match(/Обязательства применённых паттернов термина a/g) || []).length, 1);
  assert.match(slice, /a × one\/ONE-001/);
  assert.match(slice, /a × two\/TWO-001/);
});

test('несуществующий паттерн отклоняется без версии', () => {
  const root = repository({ 'terms/a.md': entity('a', 'applies: [{ pattern: absent }]\n') });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-PATTERN-UNKNOWN'));
});

test('binding паттерна принимает только qualified ID', () => {
  const pattern = `---\nid: safe\nkind: паттерн\ncontext: auth\nname: Safe\nanchors: { exemplar: [fixtures/code.rs#run] }\n---\n# Safe\n`;
  const root = repository({ ...productFiles, 'patterns/safe.md': pattern, 'terms/a.md': entity('a', 'applies:\n  - pattern: safe\n    bindings: { reason: literal }\n') });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-PATTERN-BINDING-LITERAL'));
});

test('неизвестный relation и неверная cardinality отклоняются', () => {
  const root = repository({
    'terms/a.md': entity('a', 'relations:\n  unknown: auth.b\n  references: auth.b\n'),
    'terms/b.md': entity('b'),
  });
  const findings = lint(loadRepo(root));
  assert.ok(findings.some((finding) => finding.code === 'E-RELATION-UNKNOWN'));
  assert.ok(findings.some((finding) => finding.code === 'E-RELATION-CARDINALITY'));
});

test('процесс без причинного входа и выхода виден как незавершённый flow', () => {
  const root = repository({
    ...productFiles,
    'processes/lonely.md': `---
id: lonely
kind: процесс
context: auth
name: lonely
anchors:
  code: [fixtures/code.rs#run]
  test: [fixtures/test.yaml]
outcomes: [ok, fail]
---
# lonely
`,
  });
  const findings = lint(loadRepo(root));
  assert.ok(findings.some((finding) => finding.code === 'W-PROCESS-NO-TRIGGER'));
  assert.ok(findings.some((finding) => finding.code === 'W-PROCESS-NO-NEXT'));
});

test('subject обязан присутствовать ссылкой в prose требования', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.a]\n';
  const root = repository({ ...productFiles, 'terms/a.md': entity('a'), 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\nПроверка MAY работать.' }) });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-SUBJECT-NOT-IN-PROSE'));
});

test('нормативное предложение вне requirement отклоняется', () => {
  const root = repository({ 'terms/a.md': entity('a', '', '[[auth.a|A]] MUST работать.') });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-NORM-OUTSIDE-REQ'));
});

test('context slice загружает субъект нормы через frontmatter subjects', () => {
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.a]\n';
  const root = repository({ ...productFiles, 'terms/a.md': entity('a', '', 'Тело A.'), 'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.a|A]] MAY работать.' }) });
  assert.match(contextSlice(loadRepo(root), 'AUTH-001', 'implement'), /Тело A\./);
});

test('budget считает файлы и в режиме error не отдаёт частичный срез', () => {
  const profile = PROFILE.replace('max_files: 25', 'max_files: 1').replace('on_exhaustion: degrade_to_names', 'on_exhaustion: error');
  const requirement = 'requirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.a, auth.b]\n';
  const root = repository({
    ...productFiles,
    'terms/a.md': entity('a'),
    'terms/b.md': entity('b'),
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.a|A]] MAY работать. [[auth.b|B]] MAY работать.' }),
  }, profile);
  assert.throws(() => contextSlice(loadRepo(root), 'AUTH-001', 'implement'), /бюджет исчерпан/);
});

test('budget считает один Markdown-файл один раз, даже если из него загружены две нормы', () => {
  const profile = PROFILE
    .replace('max_files: 25', 'max_files: 1')
    .replace('on_exhaustion: degrade_to_names', 'on_exhaustion: error')
    .replace('follow: [{ edge: субъект, load: full }]', 'follow: [{ edge: обратные, load: full }]');
  const requirements = `requirements:
  AUTH-001:
    kind: разрешение
    subjects: [auth.a]
  AUTH-002:
    kind: разрешение
    subjects: [auth.a]
`;
  const body = `### AUTH-001 — Первый исход

[[auth.a|A]] MAY выбрать первый исход.

### AUTH-002 — Второй исход

[[auth.a|A]] MAY выбрать второй исход.`;
  const root = repository({
    ...productFiles,
    'terms/a.md': entity('a'),
    'terms/check.md': operation({ requirement: requirements, body }),
  }, profile);
  const slice = contextSlice(loadRepo(root), 'a', 'implement');
  assert.match(slice, /AUTH-001/);
  assert.match(slice, /AUTH-002/);
});

test('outcomes находит frontmatter requirement и code anchor', () => {
  const page = `---\nid: check\nkind: операция\ncontext: auth\nname: check\nanchors:\n  code: [fixtures/code.ts#check]\n  test: [fixtures/test.yaml]\nrequirements:\n  AUTH-001:\n    kind: разрешение\n    subjects: [auth.check]\n    outcomes: [ok, fail]\n---\n# check\n### AUTH-001 — X\n[[auth.check|Check]] MAY вернуть исход.\n`;
  const root = repository({
    'terms/check.md': page,
    'fixtures/code.ts': "type Outcome = 'ok' | 'fail';\nfunction check(): Outcome { return 'ok'; }\n",
    'fixtures/test.yaml': 'ok: true\n',
  });
  const result = cmdOutcomes(loadRepo(root), 'AUTH-001');
  assert.match(result.text, /СОПОСТАВЛЕНИЕ ВРУЧНУЮ/);
  assert.match(result.text, /исходы спеки:\s+ok, fail/);
});

test('outcomes не считает сверку полной при unresolved даже с outcome_map', () => {
  const page = `---
id: check
kind: операция
context: auth
name: check
anchors:
  code: [fixtures/code.rs#check]
  test: [fixtures/test.yaml]
requirements:
  AUTH-001:
    kind: разрешение
    subjects: [auth.check]
    outcomes: [ok, fail]
outcome_map:
  AUTH-001: { Ok: ok, Err: fail }
---
# check
### AUTH-001 — X
[[auth.check|Check]] MAY вернуть исход.
`;
  const root = repository({
    'terms/check.md': page,
    'fixtures/code.rs': 'pub fn check() -> Result<(), ExternalError> { todo!() }\n',
    'fixtures/test.yaml': 'ok: true\n',
  });
  const result = cmdOutcomes(loadRepo(root), 'AUTH-001');
  assert.equal(result.status, 'unchecked');
  assert.match(result.text, /ExternalError/);
});

test('причинный срез Tessera проходит от PAM-интерфейса до session registry', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const flow = traceFlow(loadRepo(root, path.dirname(root)), 'pam-conversation');
  const chain = flow.edges.map((edge) => `${edge.from}:${edge.relation}:${edge.to}`);
  assert.ok(chain.includes('pam-conversation:starts:pkcs12-login'));
  assert.ok(chain.includes('pkcs12-login:emits:authentication-proven'));
  assert.ok(chain.includes('authentication-proven:reacts_to:session-registration-policy'));
  assert.ok(chain.includes('session-registration-policy:issues:open-monitored-session'));
  assert.ok(chain.includes('open-monitored-session:writes:session-registry'));
});

test('draft строит profile-aware каркас и ничего не записывает', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const draft = draftPage(loadRepo(root, path.dirname(root)), 'процесс', 'issuance.future-flow', 'Будущий процесс');
  assert.match(draft, /id: future-flow/);
  assert.match(draft, /kind: процесс/);
  assert.match(draft, /outcomes:/);
  assert.match(draft, /TODO:code:path#symbol/);
  assert.match(draft, /TODO:test:path#symbol/);
  assert.ok(!fs.existsSync(path.join(root, 'processes/issuance/future-flow.md')));
});

test('trace связывает норму с субъектом, evidence, реализацией и outcomes', () => {
  const requirement = `requirements:
  AUTH-001:
    kind: инвариант
    subjects: [auth.check]
    evidence:
      test: [fixtures/test.yaml]
    outcomes: [ok, fail]
`;
  const root = repository({
    ...productFiles,
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — Проверка\n\n[[auth.check|Проверка]] MUST завершаться.' }),
  });
  const rows = buildTrace(loadRepo(root), { target: 'AUTH-001' });
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].outcomes, ['ok', 'fail']);
  assert.equal(rows[0].subjects[0].id, 'auth.check');
  assert.ok(rows[0].subjects[0].anchors.some((anchor) => anchor.type === 'code'));
  assert.ok(rows[0].evidence.some((anchor) => anchor.type === 'test' && anchor.ok));
  assert.deepEqual(rows[0].gaps, []);
  assert.match(formatTrace(rows), /AUTH-001/);
});

test('decided_by создаёт точную связь нормы с решением и виден в trace', () => {
  const requirement = `requirements:
  AUTH-001:
    kind: инвариант
    decided_by: [auth.ADR-001]
    subjects: [auth.check]
    evidence: { test: [fixtures/test.yaml] }
`;
  const root = repository({
    ...productFiles,
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.check|Проверка]] MUST работать.' }),
    'decisions/adr.md': decisionPage({ id: 'ADR-001' }),
  });
  const repo = loadRepo(root);
  assert.deepEqual(repo.requirementsById.get('AUTH-001').req.decidedBy, ['auth.ADR-001']);
  assert.deepEqual(buildTrace(repo, { target: 'AUTH-001' })[0].decisions, ['auth.ADR-001']);
  assert.ok(buildGraph(repo).edges.some((edge) => edge.from === 'AUTH-001' && edge.to === 'ADR-001' && edge.relation === 'decided_by'));
});

test('принятое replacement вычисляет старому ADR effective status заменено', () => {
  const requirement = `requirements:
  AUTH-001:
    kind: инвариант
    decided_by: [auth.ADR-001]
    subjects: [auth.check]
    evidence: { test: [fixtures/test.yaml] }
`;
  const root = repository({
    ...productFiles,
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.check|Проверка]] MUST работать.' }),
    'decisions/old.md': decisionPage({ id: 'ADR-001' }),
    'decisions/new.md': decisionPage({ id: 'ADR-002', relations: '  affects: [auth.check]\n  replaces: [auth.ADR-001]' }),
  });
  const repo = loadRepo(root);
  const index = decisionIndex(repo);
  assert.equal(effectiveDecisionStatus(index.get('auth.ADR-001'), index), 'заменено');
  assert.equal(decisionReport(repo, 'auth.ADR-001').effectiveStatus, 'заменено');
  assert.ok(lint(repo).some((finding) => finding.code === 'W-REQ-SUPERSEDED-DECISION'));
});

test('предложенное replacement не меняет effective status принятого ADR', () => {
  const root = repository({
    ...productFiles,
    'terms/check.md': operation(),
    'decisions/old.md': decisionPage({ id: 'ADR-001' }),
    'decisions/new.md': decisionPage({ id: 'ADR-002', status: 'предложено', relations: '  affects: [auth.check]\n  replaces: [auth.ADR-001]' }),
  });
  const repo = loadRepo(root);
  const index = decisionIndex(repo);
  assert.equal(effectiveDecisionStatus(index.get('auth.ADR-001'), index), 'принято');
  assert.deepEqual(decisionReport(repo, 'auth.ADR-001').pendingSuccessors, [{ source: 'auth.ADR-002', relation: 'replaces' }]);
});

test('decided_by требует qualified ID решения', () => {
  const requirement = `requirements:
  AUTH-001:
    kind: инвариант
    decided_by: [ADR-001]
    subjects: [auth.check]
    evidence: { test: [fixtures/test.yaml] }
`;
  const root = repository({
    ...productFiles,
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.check|Проверка]] MUST работать.' }),
    'decisions/old.md': decisionPage({ id: 'ADR-001' }),
  });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-DECIDED-BY-QUALIFIED'));
});

test('цикл replaces/revokes отклоняется', () => {
  const root = repository({
    ...productFiles,
    'terms/check.md': operation(),
    'decisions/a.md': decisionPage({ id: 'ADR-001', relations: '  affects: [auth.check]\n  replaces: [auth.ADR-002]' }),
    'decisions/b.md': decisionPage({ id: 'ADR-002', relations: '  affects: [auth.check]\n  revokes: [auth.ADR-001]' }),
  });
  assert.ok(lint(loadRepo(root)).some((finding) => finding.code === 'E-DECISION-CYCLE'));
});

test('trace --missing показывает недостающее evidence и implementation anchor', () => {
  const requirement = `requirements:
  AUTH-001:
    kind: инвариант
    subjects: [auth.a]
`;
  const root = repository({
    'terms/a.md': `---
id: a
kind: сущность
context: auth
name: a
no_anchor: { code: external, type: external }
---
# a
`,
    'terms/check.md': operation({ requirement, body: '### AUTH-001 — X\n\n[[auth.a|A]] MUST работать.' }),
    ...productFiles,
  });
  const rows = buildTrace(loadRepo(root), { missingOnly: true });
  assert.equal(rows.length, 1);
  assert.ok(rows[0].gaps.some((gap) => gap.startsWith('missing-evidence:')));
});

test('причинный срез выпуска проходит от CLI до credential и журнала', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const flow = traceFlow(loadRepo(root, path.dirname(root)), 'issuer-cli');
  const chain = flow.edges.map((edge) => `${edge.from}:${edge.relation}:${edge.to}`);
  assert.ok(chain.includes('issuer-cli:starts:leaf-certificate-issuance'));
  assert.ok(chain.includes('leaf-certificate-issuance:invokes:issue-leaf-certificate'));
  assert.ok(chain.includes('issue-leaf-certificate:emits:leaf-certificate-issued'));
  assert.ok(chain.includes('issue-leaf-certificate:produces:credential'));
  assert.ok(chain.includes('issue-leaf-certificate:writes:issuance-journal'));
});

test('реальная Tessera не содержит ошибок и строит насыщенный граф', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const repo = loadRepo(root, path.dirname(root));
  assert.deepEqual(lint(repo).filter((finding) => finding.level === 'ERROR'), []);
  const graph = buildGraph(repo);
  assert.ok(graph.nodes.length >= 80);
  assert.ok(graph.edges.length >= 300);
});

test('реальные страницы не содержат старой машинной разметки', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const repo = loadRepo(root, path.dirname(root));
  for (const file of repo.files) {
    assert.doesNotMatch(file.raw, /\[\[[^\]]+:[^\]]+\]\]/, file.path);
    assert.doesNotMatch(file.raw, /\{#[A-Za-z]/, file.path);
    assert.doesNotMatch(file.raw, /^\*\*(?:Evidence|Outcomes|Partition)/m, file.path);
    assert.doesNotMatch(file.raw, /^\s+version:\s*\d+/m, file.path);
  }
});
