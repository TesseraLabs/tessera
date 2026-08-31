import test from 'node:test';
import assert from 'node:assert/strict';
import { extractOutcomes } from './typescript.mjs';

test('extractOutcomes (ts): enum — declared из членов, confidence exact', () => {
  const source = "export enum Status {\n  Revoked,\n  Valid = 'valid',\n}\n";
  const r = extractOutcomes(source, 'Status');
  assert.deepEqual(r.declared, ['Revoked', 'Valid']);
  assert.equal(r.confidence, 'exact');
  assert.deepEqual(r.escaping, []);
});

test('extractOutcomes (ts): union-алиас со строковыми литералами и ссылкой на enum', () => {
  const source = [
    "export enum Extra { X, Y }",
    "export type Status = 'ok' | 'fail' | Extra;",
  ].join('\n');
  const r = extractOutcomes(source, 'Status');
  assert.deepEqual(r.declared, ['ok', 'fail', 'X', 'Y']);
  assert.equal(r.confidence, 'syntactic');
});

test('extractOutcomes (ts): размеченный union по полю kind', () => {
  const source = [
    'type Result =',
    "  | { kind: 'ok'; value: number }",
    "  | { kind: 'error'; message: string };",
  ].join('\n');
  const r = extractOutcomes(source, 'Result');
  assert.deepEqual(r.declared, ['ok', 'error']);
});

test('extractOutcomes (ts): тип возврата функции по якорю разворачивается до union', () => {
  const source = [
    "type Outcome = 'ok' | 'notFound';",
    'function check(id: string): Outcome {',
    "  if (!id) throw new NotFoundError('missing id');",
    "  return 'ok';",
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'check');
  assert.deepEqual(r.declared, ['ok', 'notFound']);
  assert.equal(r.confidence, 'syntactic');
  assert.deepEqual(r.escaping, ['throw new NotFoundError']);
});

test('extractOutcomes (ts): throw foo; и Promise.reject( — escaping', () => {
  const source = [
    'function process(input: unknown): void {',
    '  const err = new Error("bad");',
    '  if (!input) throw err;',
    '  Promise.reject(new Error("async"));',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'process');
  assert.ok(r.escaping.includes('throw err'));
  assert.ok(r.escaping.includes('Promise.reject('));
});

test('extractOutcomes (ts): throw с неразобранным выражением попадает в unresolved, а не теряется', () => {
  const source = [
    'function dispatch(key: string): void {',
    '  throw errorMap[key];',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'dispatch');
  assert.deepEqual(r.escaping, []);
  assert.ok(r.unresolved.some((u) => u.includes('errorMap[key]')));
});

test('extractOutcomes (ts): функция без аннотации возврата — confidence shallow', () => {
  const source = 'function untyped(x) {\n  return x + 1;\n}\n';
  const r = extractOutcomes(source, 'untyped');
  assert.equal(r.confidence, 'shallow');
  assert.deepEqual(r.declared, []);
});

test('extractOutcomes (js): JS-файл — работает только escaping-часть, без типов', () => {
  const source = [
    'function run(input) {',
    '  if (!input) throw new Error("bad input");',
    '  return input;',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'run');
  assert.deepEqual(r.declared, []);
  assert.equal(r.confidence, 'shallow');
  assert.deepEqual(r.escaping, ['throw new Error']);
});

test('extractOutcomes (ts): символ не найден — null', () => {
  const source = 'function foo() {}\n';
  assert.equal(extractOutcomes(source, 'Nope'), null);
});

test('extractOutcomes (ts) [C7]: throw без завершающей точки с запятой (ASI) не теряется', () => {
  // Тело намеренно не содержит НИ ОДНОЙ ";" после throw — старый THROW_STMT_RE
  // требовал ";" и на этом входе не находил throw вовсе (см. REVIEW.md C7).
  const source = 'export function f(): number {\n  throw new Error("boom")\n}\n';
  const r = extractOutcomes(source, 'f');
  assert.ok(r.escaping.includes('throw new Error'), `throw без ";" потерян бесследно: escaping=${JSON.stringify(r.escaping)} unresolved=${JSON.stringify(r.unresolved)} (C7)`);
});

test('extractOutcomes (ts) [C7]: throw без ";" внутри if не тянет захват через чужую точку с запятой', () => {
  const source = [
    'export function f(x: boolean): number {',
    '  if (x) { throw new Error("boom") }',
    '  return 1;',
    '}',
  ].join('\n');
  const r = extractOutcomes(source, 'f');
  assert.ok(r.escaping.includes('throw new Error'), `throw не найден: ${JSON.stringify(r.escaping)} (C7)`);
  assert.ok(!r.escaping.some((s) => s.includes('return')), `выражение throw растянулось за пределы своей "}" и захватило соседний код: ${JSON.stringify(r.escaping)} (C7)`);
});

test('extractOutcomes (ts) [C6]: закомментированное объявление enum не затмевает настоящее', () => {
  const source = '// enum Status { Fake }\nexport enum Status { Real }\n';
  const r = extractOutcomes(source, 'Status');
  assert.deepEqual(r.declared, ['Real'], `нашёл закомментированный enum вместо настоящего: ${JSON.stringify(r.declared)} (C6)`);
});
