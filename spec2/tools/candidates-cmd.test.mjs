import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadRepo } from './graph.mjs';
import { scanCandidates, cmdCandidates, loadVerdicts } from './candidates-cmd.mjs';

/**
 * Строит фикстуру: временный productRoot (исходники) + временный spec2Root
 * (profile.yaml с секцией candidates, опционально spec-файлы и candidates.yaml).
 * @param {{ productFiles: Record<string,string>, specFiles?: Record<string,string>,
 *   candidatesYaml?: string|null, weights?: Record<string,number>, threshold?: number }} opts
 * @returns {import('./graph.mjs').Repo}
 */
function makeFixtureRepo({ productFiles, specFiles = {}, candidatesYaml = null, weights = {}, threshold = 1 }) {
  const productRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'spec2-candidates-product-'));
  const spec2Root = fs.mkdtempSync(path.join(os.tmpdir(), 'spec2-candidates-spec2-'));
  for (const [rel, content] of Object.entries(productFiles)) {
    const full = path.join(productRoot, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  const weightsYaml = Object.entries(weights).map(([k, v]) => `    ${k}: ${v}`).join('\n');
  fs.writeFileSync(
    path.join(spec2Root, 'profile.yaml'),
    `sources: [terms, processes, patterns, decisions, events, contracts, interfaces, persistence]\ncandidates:\n  threshold: ${threshold}\n  weights:\n${weightsYaml || '    {}'}\n`,
    'utf8',
  );
  for (const [rel, content] of Object.entries(specFiles)) {
    const full = path.join(spec2Root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  if (candidatesYaml !== null) fs.writeFileSync(path.join(spec2Root, 'candidates.yaml'), candidatesYaml, 'utf8');
  return loadRepo(spec2Root, productRoot);
}

function find(candidates, name) {
  return candidates.find((c) => c.name === name);
}

test('candidates: cross-module ref, публичная сигнатура, сериализация, доменный модуль — newtype НЕ отсеивается', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/domain_contract/src/lib.rs': [
        '#[derive(Debug, Serialize, Deserialize)]',
        'pub struct TicketNumber(u64);',
        '',
        'pub fn issue() -> TicketNumber { TicketNumber(1) }',
      ].join('\n'),
      'crates/other_crate/src/lib.rs': [
        'use domain_contract::TicketNumber;',
        'fn use_it(t: TicketNumber) { let _ = t; }',
      ].join('\n'),
    },
  });
  const all = scanCandidates(repo);
  const c = find(all, 'TicketNumber');
  assert.ok(c, 'newtype-обёртка над примитивом обязана попасть в кандидаты, не быть отсеянной по структуре');
  assert.equal(c.signals.crossModuleRefs, 1);
  assert.equal(c.signals.publicSignature, true);
  assert.equal(c.signals.serialization, true);
  assert.equal(c.signals.domainModule, true);
  assert.equal(c.signals.genericName, false);
  assert.ok(c.weight > 0);
});

test('candidates: generic_name — родовое имя (суффикс Config) вычитается из веса', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/foo/src/lib.rs': 'pub struct FooConfig { pub x: u32 }\n',
    },
  });
  const c = find(scanCandidates(repo), 'FooConfig');
  assert.equal(c.signals.genericName, true);
  assert.ok(c.weight < 0, `ожидали отрицательный вес у родового имени без внешнего использования, получили ${c.weight}`);
});

test('candidates: util_module — модуль с "util" в пути вычитается из веса', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/tessera_core/src/util/helpers.rs': [
        'pub struct HelperThing { pub x: u32 }',
        'pub fn touch(h: HelperThing) { let _ = h; }',
      ].join('\n'),
      'crates/other/src/lib.rs': 'use tessera_core::util::helpers::HelperThing;\nfn f(h: HelperThing) { let _ = h; }\n',
    },
  });
  const c = find(scanCandidates(repo), 'HelperThing');
  assert.equal(c.signals.utilModule, true);
});

test('candidates: no_usage — нет ни кросс-модульных ссылок, ни публичной сигнатуры', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/lonely/src/lib.rs': [
        'struct NotPublicHelper;',
        'pub struct Isolated { x: u32 }',
        'fn only_here(v: Isolated) { let _ = v; }', // не pub fn — не публичная сигнатура
      ].join('\n'),
    },
  });
  const c = find(scanCandidates(repo), 'Isolated');
  assert.equal(c.signals.crossModuleRefs, 0);
  assert.equal(c.signals.publicSignature, false);
  assert.equal(c.signals.noUsage, true);
});

test('candidates: error_or_audit — имя встречается на строке с error/audit/event', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/revocation/src/lib.rs': [
        'pub struct CrlSnapshot { pub fetched_at: u64 }',
        'pub fn check(s: CrlSnapshot) -> bool { true }',
      ].join('\n'),
      'crates/revocation/src/log.rs': [
        'fn report(s: &CrlSnapshot) {',
        '    tracing::error!("stale snapshot {:?}", CrlSnapshot::describe(s));',
        '}',
      ].join('\n'),
    },
  });
  const c = find(scanCandidates(repo), 'CrlSnapshot');
  assert.equal(c.signals.errorOrAudit, true);
  assert.equal(c.signals.genericName, false, 'CrlSnapshot не должен считаться родовым именем');
});

test('candidates: vocabulary_overlap — имя пересекается с aliases термина (латиница)', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/codes/src/lib.rs': 'pub struct TicketNumber(u64);\n',
    },
    specFiles: {
      'terms/codes/ticket.md': [
        '---', 'id: ticket', 'kind: сущность', 'context: codes', 'name: Ticket Number',
        'aliases: [TicketNumber]',
        '---', '', '# Ticket Number',
      ].join('\n'),
    },
  });
  const c = find(scanCandidates(repo), 'TicketNumber');
  assert.equal(c.signals.vocabularyOverlap, true);
});

test('candidates: уже покрытые type:-якорем не попадают в очередь вовсе', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/codes/src/lib.rs': 'pub struct TicketNumber(u64);\n',
    },
    specFiles: {
      'terms/codes/ticket.md': [
        '---', 'id: ticket', 'kind: сущность', 'context: codes', 'name: Ticket Number',
        'anchors:', '  type: [crates/codes/src/lib.rs#TicketNumber]',
        '---', '', '# Ticket Number',
      ].join('\n'),
    },
  });
  assert.equal(find(scanCandidates(repo), 'TicketNumber'), undefined);
});

test('candidates: schema:-якорь покрывает опубликованный тип контракта', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/proto/src/lib.rs': 'pub struct ClientMessage { pub version: u32 }\n',
    },
    specFiles: {
      'contracts/runtime/ipc.md': [
        '---', 'id: ipc', 'kind: контракт', 'context: runtime', 'name: IPC',
        'anchors:', '  schema: [crates/proto/src/lib.rs#ClientMessage]',
        '---', '', '# IPC',
      ].join('\n'),
    },
  });
  assert.equal(find(scanCandidates(repo), 'ClientMessage'), undefined);
});

test('candidates: кандидат с записанным вердиктом не попадает ни в полный вывод, ни в --new', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/codes/src/lib.rs': [
        'pub struct TicketNumber(u64);',
        'pub fn issue() -> TicketNumber { TicketNumber(1) }',
      ].join('\n'),
      'crates/other/src/lib.rs': 'use codes::TicketNumber;\nfn f(t: TicketNumber) { let _ = t; }\n',
    },
    candidatesYaml: 'crates/codes/src/lib.rs#TicketNumber:\n  verdict: термин\n  term_id: ticket-number\n',
  });
  const verdicts = loadVerdicts(repo.root);
  assert.equal(verdicts.get('crates/codes/src/lib.rs#TicketNumber').verdict, 'термин');

  const full = cmdCandidates(repo, {});
  assert.ok(!full.text.includes('TicketNumber'));
  const onlyNew = cmdCandidates(repo, { onlyNew: true });
  assert.equal(onlyNew.hasNew, false);
  assert.ok(!onlyNew.text.includes('TicketNumber'));
});

test('candidates --new: без вердикта — hasNew=true, перечисляет кандидата', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/codes/src/lib.rs': [
        'pub struct TicketNumber(u64);',
        'pub fn issue() -> TicketNumber { TicketNumber(1) }',
      ].join('\n'),
      'crates/other/src/lib.rs': 'use codes::TicketNumber;\nfn f(t: TicketNumber) { let _ = t; }\n',
    },
  });
  const { text, hasNew } = cmdCandidates(repo, { onlyNew: true });
  assert.equal(hasNew, true);
  assert.match(text, /TicketNumber/);
});

test('candidates: полный вывод ранжирован по убыванию веса и содержит расшифровку сигналов', () => {
  const repo = makeFixtureRepo({
    productFiles: {
      'crates/domain_contract/src/lib.rs': [
        '#[derive(Serialize, Deserialize)]',
        'pub struct Strong(u64);',
        'pub fn issue() -> Strong { Strong(1) }',
        'pub struct WeakConfig { pub x: u32 }',
      ].join('\n'),
      'crates/other/src/lib.rs': 'use domain_contract::Strong;\nfn f(s: Strong) { let _ = s; }\n',
    },
    threshold: -100, // не отфильтровывать слабый кандидат в этом тесте
  });
  const { text } = cmdCandidates(repo, {});
  const strongLine = text.split('\n').find((l) => l.includes('Strong') && !l.includes('WeakConfig'));
  const weakLine = text.split('\n').find((l) => l.includes('WeakConfig'));
  assert.ok(strongLine && weakLine, 'оба кандидата должны присутствовать при отрицательном threshold');
  assert.ok(text.indexOf(strongLine) < text.indexOf(weakLine), 'сильный кандидат обязан идти раньше слабого');
  assert.match(strongLine, /cross_module_ref×1/);
});

test('candidates: порог из profile.yaml отфильтровывает слабых кандидатов из полного вывода', () => {
  const repo = makeFixtureRepo({
    productFiles: { 'crates/foo/src/lib.rs': 'pub struct FooConfig { pub x: u32 }\n' },
    threshold: 1,
  });
  const { text } = cmdCandidates(repo, {});
  assert.ok(!text.includes('FooConfig'));
});
